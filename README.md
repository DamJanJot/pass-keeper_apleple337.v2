# Pass Keeper 🔐

Terminalowy menedżer haseł napisany w Pythonie, stworzony jako projekt edukacyjny do nauki podstaw kryptografii i programowania.

## Funkcje
- Dodawanie, wyświetlanie, listowanie i usuwanie haseł
- Szyfrowanie danych przy użyciu Fernet (AES) z biblioteki `cryptography`
- Klucz szyfrujący generowany z hasła głównego przy pomocy PBKDF2 (600 000 iteracji)
- Dane przechowywane lokalnie w zaszyfrowanej formie (plik JSON)
- Ukryte wpisywanie haseł w terminalu (`getpass`)

## Wymagania
- Python 3.10+
- Biblioteka `cryptography`

## Instalacja i uruchomienie

```bash
git clone <link-do-repo>
cd pass_keeper
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 main.py
```

## ⚠️ Uwaga dotycząca bezpieczeństwa

To jest **projekt edukacyjny**, stworzony w celu nauki podstaw kryptografii i bezpiecznego przechowywania danych. Nie był poddany profesjonalnemu audytowi bezpieczeństwa i **nie jest przeznaczony do przechowywania rzeczywistych, ważnych haseł**. Do codziennego użytku polecam sprawdzone rozwiązania jak Bitwarden czy KeePassXC.

## Czego się nauczyłem
- Bezpieczne wyprowadzanie klucza z hasła (PBKDF2 + sól)
- Szyfrowanie symetryczne (Fernet)
- Obsługa wyjątków w Pythonie
- Praca z plikami JSON i kodowaniem base64
- Projektowanie prostego CLI z zarządzaniem stanem
