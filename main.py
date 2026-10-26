"""Pass Keeper - lokalny, szyfrowany menedzer hasel w terminalu."""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
from pathlib import Path
import secrets
import shutil
import string
import tempfile
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


APP_VERSION = "2.0.0"
FORMAT_VERSION = 2
DEFAULT_ITERATIONS = 600_000
MIN_ITERATIONS = 100_000
MAX_ITERATIONS = 10_000_000
ARGON2_ITERATIONS = 2
ARGON2_LANES = 1
ARGON2_MEMORY_COST = 19 * 1024
MAX_ARGON2_ITERATIONS = 20
MAX_ARGON2_LANES = 16
MAX_ARGON2_MEMORY_COST = 256 * 1024
MIN_MASTER_PASSWORD_LENGTH = 12
DEFAULT_PASSWORD_LENGTH = 20
DATA_FILE = "passwords.json"

LOGO = r"""
+=======================================+
|          PASS KEEPER  v2.0            |
|     lokalny, szyfrowany sejf CLI      |
+=======================================+
"""


class VaultError(Exception):
    """Bazowy blad sejfu."""


class InvalidMasterPassword(VaultError):
    """Haslo glowne nie odblokowalo sejfu."""


class VaultFormatError(VaultError):
    """Plik sejfu jest uszkodzony albo ma nieobslugiwany format."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def generate_key(
    password: str,
    salt: bytes,
    iterations: int = DEFAULT_ITERATIONS,
) -> bytes:
    """Wyprowadz klucz Fernet z hasla i losowej soli."""
    if not isinstance(password, str) or not password:
        raise ValueError("Haslo nie moze byc puste.")
    if not isinstance(salt, bytes) or len(salt) < 16:
        raise ValueError("Sol musi miec co najmniej 16 bajtow.")
    if not MIN_ITERATIONS <= iterations <= MAX_ITERATIONS:
        raise ValueError("Nieobslugiwana liczba iteracji KDF.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def generate_argon2_key(
    password: str,
    salt: bytes,
    *,
    iterations: int = ARGON2_ITERATIONS,
    lanes: int = ARGON2_LANES,
    memory_cost: int = ARGON2_MEMORY_COST,
) -> bytes:
    """Wyprowadz klucz Fernet przy pomocy pamiecioodpornego Argon2id."""
    if not isinstance(password, str) or not password:
        raise ValueError("Haslo nie moze byc puste.")
    if not isinstance(salt, bytes) or len(salt) < 16:
        raise ValueError("Sol musi miec co najmniej 16 bajtow.")
    if not 1 <= iterations <= MAX_ARGON2_ITERATIONS:
        raise ValueError("Nieobslugiwana liczba przebiegow Argon2id.")
    if not 1 <= lanes <= MAX_ARGON2_LANES:
        raise ValueError("Nieobslugiwana liczba watkow Argon2id.")
    if not 8 * lanes <= memory_cost <= MAX_ARGON2_MEMORY_COST:
        raise ValueError("Nieobslugiwany koszt pamieci Argon2id.")

    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=iterations,
        lanes=lanes,
        memory_cost=memory_cost,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def _new_kdf_metadata() -> dict[str, Any]:
    return {
        "algorithm": "Argon2id",
        "iterations": ARGON2_ITERATIONS,
        "lanes": ARGON2_LANES,
        "memory_cost": ARGON2_MEMORY_COST,
        "salt": base64.urlsafe_b64encode(secrets.token_bytes(16)).decode("ascii"),
    }


def _derive_document_key(password: str, kdf_data: Any) -> bytes:
    if not isinstance(kdf_data, dict):
        raise VaultFormatError("Nieprawidlowa konfiguracja KDF.")
    try:
        algorithm = kdf_data["algorithm"]
        salt = _decode_salt(kdf_data["salt"])
    except KeyError as exc:
        raise VaultFormatError("Brak wymaganych pol konfiguracji KDF.") from exc

    if algorithm == "Argon2id":
        iterations = _read_bounded_int(
            kdf_data.get("iterations"),
            "liczba przebiegow Argon2id",
            1,
            MAX_ARGON2_ITERATIONS,
        )
        lanes = _read_bounded_int(
            kdf_data.get("lanes"),
            "liczba watkow Argon2id",
            1,
            MAX_ARGON2_LANES,
        )
        memory_cost = _read_bounded_int(
            kdf_data.get("memory_cost"),
            "koszt pamieci Argon2id",
            8 * lanes,
            MAX_ARGON2_MEMORY_COST,
        )
        return generate_argon2_key(
            password,
            salt,
            iterations=iterations,
            lanes=lanes,
            memory_cost=memory_cost,
        )

    if algorithm == "PBKDF2-HMAC-SHA256":
        return generate_key(password, salt, _read_iterations(kdf_data.get("iterations")))

    raise VaultFormatError("Nieobslugiwany algorytm KDF.")


def encrypt_password(password: str, key: bytes) -> bytes:
    """Zgodna ze stara wersja funkcja szyfrujaca pojedynczy tekst."""
    return Fernet(key).encrypt(password.encode("utf-8"))


def decrypt_password(encrypted_password: bytes, key: bytes) -> str:
    """Zgodna ze stara wersja funkcja odszyfrowujaca pojedynczy tekst."""
    return Fernet(key).decrypt(encrypted_password).decode("utf-8")


def validate_new_master_password(password: str) -> None:
    if len(password) < MIN_MASTER_PASSWORD_LENGTH:
        raise ValueError(
            f"Haslo glowne musi miec co najmniej {MIN_MASTER_PASSWORD_LENGTH} znakow."
        )
    if password.isspace():
        raise ValueError("Haslo glowne nie moze skladac sie tylko ze spacji.")


def generate_password(
    length: int = DEFAULT_PASSWORD_LENGTH,
    *,
    lowercase: bool = True,
    uppercase: bool = True,
    digits: bool = True,
    symbols: bool = True,
) -> str:
    """Wygeneruj haslo z gwarancja uzycia kazdej wybranej grupy znakow."""
    groups: list[str] = []
    if lowercase:
        groups.append(string.ascii_lowercase)
    if uppercase:
        groups.append(string.ascii_uppercase)
    if digits:
        groups.append(string.digits)
    if symbols:
        groups.append("!@#$%^&*()-_=+[]{}:,.?")

    if not groups:
        raise ValueError("Wybierz co najmniej jedna grupe znakow.")
    if length < max(8, len(groups)) or length > 256:
        raise ValueError("Dlugosc hasla musi miescic sie w zakresie 8-256.")

    chars = [secrets.choice(group) for group in groups]
    alphabet = "".join(groups)
    chars.extend(secrets.choice(alphabet) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


class VaultStore:
    """Obsluga zaszyfrowanego pliku sejfu w formacie v2."""

    def __init__(self, path: str | Path = DATA_FILE) -> None:
        self.path = Path(path)
        self._document: dict[str, Any] | None = None
        self._payload: dict[str, Any] | None = None
        self._key: bytes | None = None
        self.migration_backup: Path | None = None

    @property
    def exists(self) -> bool:
        return self.path.exists()

    @property
    def unlocked(self) -> bool:
        return self._payload is not None and self._key is not None

    @property
    def entries(self) -> list[dict[str, str]]:
        self._require_unlocked()
        assert self._payload is not None
        return sorted(
            self._payload["entries"],
            key=lambda entry: (entry["name"].casefold(), entry["username"].casefold()),
        )

    def create(self, master_password: str) -> None:
        validate_new_master_password(master_password)
        if self.exists:
            raise VaultError(f"Plik sejfu juz istnieje: {self.path}")

        now = utc_now()
        self._payload = {
            "created_at": now,
            "updated_at": now,
            "entries": [],
        }
        kdf_data = _new_kdf_metadata()
        key = _derive_document_key(master_password, kdf_data)
        self._write_encrypted(key, kdf_data)

    def unlock(self, master_password: str) -> None:
        document = self._read_document()
        if document.get("version") == FORMAT_VERSION:
            self._unlock_v2(document, master_password)
            return
        if "salt" in document and "passwords" in document:
            self._migrate_legacy(document, master_password)
            return
        raise VaultFormatError("Nieobslugiwany format pliku sejfu.")

    def lock(self) -> None:
        self._key = None
        self._payload = None
        self._document = None

    def verify_master_password(self, password: str) -> bool:
        self._require_unlocked()
        assert self._document is not None
        try:
            self._decode_v2(self._document, password)
        except (InvalidMasterPassword, VaultFormatError, ValueError):
            return False
        return True

    def add_entry(
        self,
        name: str,
        password: str,
        *,
        username: str = "",
        url: str = "",
        notes: str = "",
    ) -> dict[str, str]:
        self._require_unlocked()
        clean_name = name.strip()
        if not clean_name:
            raise ValueError("Nazwa wpisu nie moze byc pusta.")
        if not password:
            raise ValueError("Haslo wpisu nie moze byc puste.")
        if self.get_entry_by_name(clean_name) is not None:
            raise ValueError("Wpis o tej nazwie juz istnieje.")

        now = utc_now()
        entry = {
            "id": uuid4().hex,
            "name": clean_name,
            "username": username.strip(),
            "password": password,
            "url": url.strip(),
            "notes": notes.strip(),
            "created_at": now,
            "updated_at": now,
        }
        assert self._payload is not None
        self._payload["entries"].append(entry)
        self.save()
        return entry.copy()

    def update_entry(self, entry_id: str, **changes: str) -> dict[str, str]:
        entry = self.get_entry(entry_id)
        allowed = {"name", "username", "password", "url", "notes"}
        unknown = set(changes) - allowed
        if unknown:
            raise ValueError(f"Nieznane pola: {', '.join(sorted(unknown))}")

        if "name" in changes:
            new_name = changes["name"].strip()
            if not new_name:
                raise ValueError("Nazwa wpisu nie moze byc pusta.")
            duplicate = self.get_entry_by_name(new_name)
            if duplicate is not None and duplicate["id"] != entry_id:
                raise ValueError("Wpis o tej nazwie juz istnieje.")
            changes["name"] = new_name
        if "password" in changes and not changes["password"]:
            raise ValueError("Haslo wpisu nie moze byc puste.")

        for field, value in changes.items():
            entry[field] = value if field == "password" else value.strip()
        entry["updated_at"] = utc_now()
        self.save()
        return entry.copy()

    def delete_entry(self, entry_id: str) -> dict[str, str]:
        entry = self.get_entry(entry_id)
        assert self._payload is not None
        self._payload["entries"].remove(entry)
        self.save()
        return entry.copy()

    def get_entry(self, entry_id: str) -> dict[str, str]:
        self._require_unlocked()
        assert self._payload is not None
        for entry in self._payload["entries"]:
            if entry["id"] == entry_id:
                return entry
        raise KeyError("Nie znaleziono wpisu.")

    def get_entry_by_name(self, name: str) -> dict[str, str] | None:
        self._require_unlocked()
        assert self._payload is not None
        wanted = name.casefold()
        for entry in self._payload["entries"]:
            if entry["name"].casefold() == wanted:
                return entry
        return None

    def search_entries(self, query: str) -> list[dict[str, str]]:
        self._require_unlocked()
        wanted = query.strip().casefold()
        if not wanted:
            return self.entries
        fields = ("name", "username", "url", "notes")
        return [
            entry
            for entry in self.entries
            if any(wanted in entry[field].casefold() for field in fields)
        ]

    def change_master_password(self, new_password: str) -> None:
        self._require_unlocked()
        validate_new_master_password(new_password)
        kdf_data = _new_kdf_metadata()
        key = _derive_document_key(new_password, kdf_data)
        self._write_encrypted(key, kdf_data)

    def save(self) -> None:
        self._require_unlocked()
        assert self._document is not None
        assert self._key is not None
        kdf_data = self._document["kdf"]
        self._write_encrypted(self._key, kdf_data)

    def _require_unlocked(self) -> None:
        if not self.unlocked:
            raise VaultError("Sejf jest zablokowany.")

    def _read_document(self) -> dict[str, Any]:
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                document = json.load(handle)
        except FileNotFoundError as exc:
            raise VaultError(f"Nie znaleziono sejfu: {self.path}") from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise VaultFormatError("Nie mozna odczytac pliku sejfu.") from exc
        if not isinstance(document, dict):
            raise VaultFormatError("Glowna struktura sejfu musi byc obiektem JSON.")
        return document

    def _unlock_v2(self, document: dict[str, Any], master_password: str) -> None:
        key, payload = self._decode_v2(document, master_password)
        self._document = document
        self._payload = payload
        self._key = key

    def _decode_v2(
        self,
        document: dict[str, Any],
        master_password: str,
    ) -> tuple[bytes, dict[str, Any]]:
        try:
            kdf_data = document["kdf"]
            token = document["vault"].encode("ascii")
        except (KeyError, TypeError, AttributeError, UnicodeError) as exc:
            raise VaultFormatError("Brak wymaganych pol w pliku sejfu.") from exc

        try:
            key = _derive_document_key(master_password, kdf_data)
            plaintext = Fernet(key).decrypt(token)
        except InvalidToken as exc:
            raise InvalidMasterPassword("Bledne haslo glowne.") from exc

        try:
            payload = json.loads(plaintext.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise VaultFormatError("Zaszyfrowana zawartosc sejfu jest uszkodzona.") from exc
        _validate_payload(payload)
        return key, payload

    def _write_encrypted(self, key: bytes, kdf_data: dict[str, Any]) -> None:
        assert self._payload is not None
        self._payload["updated_at"] = utc_now()
        plaintext = json.dumps(
            self._payload,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        document = {
            "version": FORMAT_VERSION,
            "kdf": dict(kdf_data),
            "vault": Fernet(key).encrypt(plaintext).decode("ascii"),
        }
        _atomic_json_write(self.path, document)
        self._document = document
        self._key = key

    def _migrate_legacy(
        self,
        document: dict[str, Any],
        master_password: str,
    ) -> None:
        try:
            salt = _decode_salt(document["salt"])
            encrypted_passwords = document["passwords"]
            if not isinstance(encrypted_passwords, dict):
                raise TypeError
            key = generate_key(master_password, salt)
            decrypted = {
                str(name): decrypt_password(str(token).encode("ascii"), key)
                for name, token in encrypted_passwords.items()
            }
        except InvalidToken as exc:
            raise InvalidMasterPassword("Bledne haslo glowne do starego sejfu.") from exc
        except (KeyError, TypeError, ValueError, UnicodeError) as exc:
            raise VaultFormatError("Stary plik sejfu jest uszkodzony.") from exc

        backup = self.path.with_name(f"{self.path.name}.v1.bak")
        if not backup.exists():
            try:
                shutil.copy2(self.path, backup)
            except OSError as exc:
                raise VaultError("Nie udalo sie utworzyc kopii starego sejfu.") from exc
        self.migration_backup = backup

        now = utc_now()
        self._payload = {
            "created_at": now,
            "updated_at": now,
            "entries": [
                {
                    "id": uuid4().hex,
                    "name": name,
                    "username": "",
                    "password": password,
                    "url": "",
                    "notes": "Zaimportowano z Pass Keeper v1",
                    "created_at": now,
                    "updated_at": now,
                }
                for name, password in decrypted.items()
            ],
        }
        kdf_data = _new_kdf_metadata()
        new_key = _derive_document_key(master_password, kdf_data)
        self._write_encrypted(new_key, kdf_data)


def _decode_salt(value: Any) -> bytes:
    if not isinstance(value, str):
        raise VaultFormatError("Nieprawidlowa sol KDF.")
    try:
        salt = base64.urlsafe_b64decode(value.encode("ascii"))
    except (ValueError, UnicodeError) as exc:
        raise VaultFormatError("Nieprawidlowe kodowanie soli KDF.") from exc
    if len(salt) < 16:
        raise VaultFormatError("Sol KDF jest zbyt krotka.")
    return salt


def _read_iterations(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise VaultFormatError("Nieprawidlowa liczba iteracji KDF.")
    if not MIN_ITERATIONS <= value <= MAX_ITERATIONS:
        raise VaultFormatError("Liczba iteracji KDF jest poza bezpiecznym zakresem.")
    return value


def _read_bounded_int(
    value: Any,
    name: str,
    minimum: int,
    maximum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise VaultFormatError(f"Nieprawidlowa wartosc: {name}.")
    if not minimum <= value <= maximum:
        raise VaultFormatError(f"Wartosc poza obslugiwanym zakresem: {name}.")
    return value


def _validate_payload(payload: Any) -> None:
    if not isinstance(payload, dict) or not isinstance(payload.get("entries"), list):
        raise VaultFormatError("Nieprawidlowa zawartosc sejfu.")
    required = {
        "id",
        "name",
        "username",
        "password",
        "url",
        "notes",
        "created_at",
        "updated_at",
    }
    for entry in payload["entries"]:
        if not isinstance(entry, dict) or not required.issubset(entry):
            raise VaultFormatError("Nieprawidlowy wpis w sejfie.")
        if not all(isinstance(entry[field], str) for field in required):
            raise VaultFormatError("Pola wpisu musza byc tekstem.")


def _atomic_json_write(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
        )
        temp_path = Path(name)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(document, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temp_path, 0o600)
        except OSError:
            pass
        os.replace(temp_path, path)
    except OSError as exc:
        raise VaultError(f"Nie udalo sie zapisac sejfu: {exc}") from exc
    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()


def _read_new_master_password() -> str:
    while True:
        password = getpass.getpass("Ustaw haslo glowne: ")
        try:
            validate_new_master_password(password)
        except ValueError as exc:
            print(f"Blad: {exc}")
            continue
        repeated = getpass.getpass("Powtorz haslo glowne: ")
        if password != repeated:
            print("Hasla nie sa takie same.")
            continue
        return password


def _unlock_or_create(store: VaultStore) -> bool:
    if not store.exists:
        print("Nie znaleziono sejfu. Utworzymy nowy.")
        store.create(_read_new_master_password())
        print(f"Utworzono sejf: {store.path.resolve()}")
        return True

    print(f"Znaleziono sejf: {store.path.resolve()}")
    for attempt in range(1, 4):
        password = getpass.getpass("Haslo glowne: ")
        try:
            store.unlock(password)
        except InvalidMasterPassword:
            print(f"Bledne haslo ({attempt}/3).")
            continue
        if store.migration_backup is not None:
            print("Sejf v1 zostal bezpiecznie przeniesiony do formatu v2.")
            print(f"Kopia starego pliku: {store.migration_backup.resolve()}")
        print("Sejf odblokowany.")
        return True
    print("Za duzo nieudanych prob. Koniec programu.")
    return False


def _ask_int(prompt: str, default: int) -> int:
    value = input(f"{prompt} [{default}]: ").strip()
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        print("Podaj liczbe calkowita. Uzywam wartosci domyslnej.")
        return default


def _print_entries(entries: list[dict[str, str]]) -> None:
    if not entries:
        print("Brak wpisow.")
        return
    print(f"{'Lp.':>3}  {'Nazwa':<24}  {'Uzytkownik':<24}  Adres")
    print("-" * 82)
    for number, entry in enumerate(entries, start=1):
        print(
            f"{number:>3}. {entry['name'][:24]:<24}  "
            f"{entry['username'][:24]:<24}  {entry['url']}"
        )


def _select_entry(store: VaultStore) -> dict[str, str] | None:
    entries = store.entries
    _print_entries(entries)
    if not entries:
        return None
    choice = input("Podaj numer albo dokladna nazwe wpisu: ").strip()
    if choice.isdigit():
        index = int(choice) - 1
        if 0 <= index < len(entries):
            return entries[index]
    entry = store.get_entry_by_name(choice)
    if entry is None:
        print("Nie znaleziono wpisu.")
    return entry


def _add_entry(store: VaultStore) -> None:
    name = input("Nazwa wpisu: ").strip()
    username = input("Login / e-mail (opcjonalnie): ").strip()
    password = getpass.getpass("Haslo (Enter = wygeneruj): ")
    if not password:
        password = generate_password(_ask_int("Dlugosc generowanego hasla", 20))
        print(f"Wygenerowane haslo: {password}")
    url = input("Adres URL (opcjonalnie): ").strip()
    notes = input("Notatka (opcjonalnie): ").strip()
    entry = store.add_entry(
        name,
        password,
        username=username,
        url=url,
        notes=notes,
    )
    print(f"Zapisano wpis: {entry['name']}")


def _show_entry(store: VaultStore) -> None:
    entry = _select_entry(store)
    if entry is None:
        return
    print("\n--- Szczegoly wpisu ---")
    print(f"Nazwa:       {entry['name']}")
    print(f"Uzytkownik:  {entry['username'] or '-'}")
    print(f"Haslo:       {entry['password']}")
    print(f"URL:         {entry['url'] or '-'}")
    print(f"Notatka:     {entry['notes'] or '-'}")
    print(f"Aktualizacja:{entry['updated_at']}")


def _edit_entry(store: VaultStore) -> None:
    entry = _select_entry(store)
    if entry is None:
        return
    print("Enter pozostawia dotychczasowa wartosc. Wpisz '-' aby wyczyscic pole.")
    changes: dict[str, str] = {}
    for field, label in (
        ("name", "Nazwa"),
        ("username", "Login / e-mail"),
        ("url", "URL"),
        ("notes", "Notatka"),
    ):
        value = input(f"{label} [{entry[field]}]: ")
        if value == "-" and field != "name":
            changes[field] = ""
        elif value:
            changes[field] = value
    password = getpass.getpass("Nowe haslo (Enter = bez zmian, /g = generuj): ")
    if password == "/g":
        password = generate_password(_ask_int("Dlugosc generowanego hasla", 20))
        print(f"Wygenerowane haslo: {password}")
        changes["password"] = password
    elif password:
        changes["password"] = password
    if not changes:
        print("Brak zmian.")
        return
    updated = store.update_entry(entry["id"], **changes)
    print(f"Zaktualizowano wpis: {updated['name']}")


def _delete_entry(store: VaultStore) -> None:
    entry = _select_entry(store)
    if entry is None:
        return
    confirmation = input(f"Usunac '{entry['name']}'? Wpisz TAK: ").strip()
    if confirmation != "TAK":
        print("Anulowano.")
        return
    store.delete_entry(entry["id"])
    print("Wpis zostal usuniety.")


def _search_entries(store: VaultStore) -> None:
    query = input("Szukaj w nazwie, loginie, URL i notatkach: ")
    _print_entries(store.search_entries(query))


def _change_master_password(store: VaultStore) -> None:
    current = getpass.getpass("Obecne haslo glowne: ")
    if not store.verify_master_password(current):
        print("Bledne obecne haslo glowne.")
        return
    new_password = _read_new_master_password()
    store.change_master_password(new_password)
    print("Haslo glowne zostalo zmienione, a sejf ponownie zaszyfrowany.")


def _run_menu(store: VaultStore) -> None:
    while True:
        print("\n--- Pass Keeper ---")
        print(f"Wpisy w sejfie: {len(store.entries)}")
        print("1. Dodaj wpis")
        print("2. Pokaz wpis")
        print("3. Lista wpisow")
        print("4. Edytuj wpis")
        print("5. Usun wpis")
        print("6. Szukaj")
        print("7. Generator hasel")
        print("8. Zmien haslo glowne")
        print("9. Zablokuj sejf")
        print("0. Wyjscie")
        choice = input("Wybierz opcje: ").strip()

        try:
            if choice == "1":
                _add_entry(store)
            elif choice == "2":
                _show_entry(store)
            elif choice == "3":
                _print_entries(store.entries)
            elif choice == "4":
                _edit_entry(store)
            elif choice == "5":
                _delete_entry(store)
            elif choice == "6":
                _search_entries(store)
            elif choice == "7":
                print(
                    "Wygenerowane haslo: "
                    + generate_password(_ask_int("Dlugosc hasla", DEFAULT_PASSWORD_LENGTH))
                )
            elif choice == "8":
                _change_master_password(store)
            elif choice == "9":
                store.lock()
                print("Sejf zablokowany.")
                if not _unlock_or_create(store):
                    return
            elif choice == "0":
                store.lock()
                print("Sejf zablokowany. Do widzenia!")
                return
            else:
                print("Nieprawidlowy wybor.")
        except (ValueError, KeyError, VaultError) as exc:
            print(f"Blad: {exc}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Lokalny, szyfrowany menedzer hasel w terminalu.",
    )
    parser.add_argument(
        "--vault",
        default=os.environ.get("PASS_KEEPER_VAULT", DATA_FILE),
        help="sciezka do pliku sejfu (domyslnie: passwords.json)",
    )
    parser.add_argument("--no-logo", action="store_true", help="nie wyswietlaj logo")
    parser.add_argument("--version", action="version", version=f"%(prog)s {APP_VERSION}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.no_logo:
        print(LOGO)
    store = VaultStore(args.vault)
    try:
        if not _unlock_or_create(store):
            return 1
        _run_menu(store)
    except (KeyboardInterrupt, EOFError):
        store.lock()
        print("\nPrzerwano. Sejf zostal zablokowany.")
        return 130
    except VaultError as exc:
        print(f"Blad sejfu: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
