import base64
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import string
import tempfile
import unittest
from unittest.mock import patch

from cryptography.fernet import Fernet

from main import (
    InvalidMasterPassword,
    VaultStore,
    encrypt_password,
    generate_key,
    generate_password,
    main as run_cli,
)


class VaultStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()
        self.vault_path = Path(self.temp_directory.name) / "vault.json"
        self.master_password = "bardzo-dlugie-haslo-testowe"

    def tearDown(self) -> None:
        self.temp_directory.cleanup()

    def test_create_save_and_unlock(self) -> None:
        store = VaultStore(self.vault_path)
        store.create(self.master_password)
        store.add_entry(
            "Poczta",
            "tajne-haslo-123",
            username="tester@example.test",
            url="https://example.test",
            notes="konto testowe",
        )

        raw_file = self.vault_path.read_text(encoding="utf-8")
        self.assertNotIn("Poczta", raw_file)
        self.assertNotIn("tajne-haslo-123", raw_file)
        self.assertNotIn("tester@example.test", raw_file)

        reopened = VaultStore(self.vault_path)
        reopened.unlock(self.master_password)
        entry = reopened.get_entry_by_name("poczta")
        self.assertIsNotNone(entry)
        assert entry is not None
        self.assertEqual(entry["password"], "tajne-haslo-123")

    def test_wrong_master_password_is_rejected(self) -> None:
        store = VaultStore(self.vault_path)
        store.create(self.master_password)
        store.lock()

        with self.assertRaises(InvalidMasterPassword):
            store.unlock("zdecydowanie-bledne-haslo")

    def test_crud_and_search(self) -> None:
        store = VaultStore(self.vault_path)
        store.create(self.master_password)
        entry = store.add_entry(
            "Serwer",
            "haslo-1",
            username="admin",
            notes="srodowisko testowe",
        )

        results = store.search_entries("testowe")
        self.assertEqual([item["id"] for item in results], [entry["id"]])

        updated = store.update_entry(
            entry["id"],
            name="Serwer demo",
            password="haslo-2",
        )
        self.assertEqual(updated["name"], "Serwer demo")
        self.assertEqual(updated["password"], "haslo-2")

        deleted = store.delete_entry(entry["id"])
        self.assertEqual(deleted["name"], "Serwer demo")
        self.assertEqual(store.entries, [])

    def test_change_master_password_reencrypts_vault(self) -> None:
        store = VaultStore(self.vault_path)
        store.create(self.master_password)
        store.add_entry("Konto", "sekret")
        new_master = "jeszcze-dluzsze-nowe-haslo"
        store.change_master_password(new_master)
        store.lock()

        with self.assertRaises(InvalidMasterPassword):
            store.unlock(self.master_password)
        store.unlock(new_master)
        self.assertEqual(store.get_entry_by_name("Konto")["password"], "sekret")

    def test_legacy_v1_file_is_migrated_with_backup(self) -> None:
        legacy_password = "stare-haslo"
        salt = b"0123456789abcdef"
        key = generate_key(legacy_password, salt)
        legacy_document = {
            "salt": base64.urlsafe_b64encode(salt).decode("ascii"),
            "passwords": {
                "Stare konto": encrypt_password("stary-sekret", key).decode("ascii")
            },
        }
        self.vault_path.write_text(
            json.dumps(legacy_document),
            encoding="utf-8",
        )

        store = VaultStore(self.vault_path)
        store.unlock(legacy_password)

        self.assertEqual(store.get_entry_by_name("Stare konto")["password"], "stary-sekret")
        self.assertTrue(self.vault_path.with_name("vault.json.v1.bak").exists())
        migrated_document = json.loads(self.vault_path.read_text(encoding="utf-8"))
        self.assertEqual(migrated_document["version"], 2)

    def test_pbkdf2_v2_file_remains_compatible(self) -> None:
        salt = b"abcdef0123456789"
        key = generate_key(self.master_password, salt)
        payload = {
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
            "entries": [],
        }
        document = {
            "version": 2,
            "kdf": {
                "algorithm": "PBKDF2-HMAC-SHA256",
                "iterations": 600_000,
                "salt": base64.urlsafe_b64encode(salt).decode("ascii"),
            },
            "vault": Fernet(key).encrypt(
                json.dumps(payload).encode("utf-8")
            ).decode("ascii"),
        }
        self.vault_path.write_text(json.dumps(document), encoding="utf-8")

        store = VaultStore(self.vault_path)
        store.unlock(self.master_password)

        self.assertTrue(store.unlocked)
        self.assertEqual(store.entries, [])


class PasswordGeneratorTests(unittest.TestCase):
    def test_generator_uses_each_selected_character_group(self) -> None:
        password = generate_password(32)
        self.assertEqual(len(password), 32)
        self.assertTrue(any(char in string.ascii_lowercase for char in password))
        self.assertTrue(any(char in string.ascii_uppercase for char in password))
        self.assertTrue(any(char in string.digits for char in password))
        self.assertTrue(any(char in "!@#$%^&*()-_=+[]{}:,.?" for char in password))

    def test_generator_rejects_too_short_password(self) -> None:
        with self.assertRaises(ValueError):
            generate_password(7)


class CliSmokeTests(unittest.TestCase):
    def test_first_start_reaches_menu_and_exits_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault_path = Path(directory) / "cli-vault.json"
            output = io.StringIO()
            with (
                patch(
                    "main.getpass.getpass",
                    side_effect=[
                        "bardzo-dlugie-haslo-testowe",
                        "bardzo-dlugie-haslo-testowe",
                    ],
                ),
                patch("builtins.input", side_effect=["0"]),
                redirect_stdout(output),
            ):
                result = run_cli(["--no-logo", "--vault", str(vault_path)])

            self.assertEqual(result, 0)
            self.assertTrue(vault_path.exists())
            self.assertIn("Sejf zablokowany. Do widzenia!", output.getvalue())


if __name__ == "__main__":
    unittest.main()
