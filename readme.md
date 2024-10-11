# Password Manager
This is a simple CLI-based password manager that works with a SQLite database. It allows passwords to be stored, managed and retrieved, with master password verification required to gain access to the database.

## Features
- Save and manage passwords for various services.
- Generation of random passwords.
- Encrypted storage of passwords.
- Masked input for passwords (both for the master password and for service passwords).
- Cross-platform support for copying passwords to the clipboard.
- Checking passwords for minimum requirements (uppercase letters, lowercase letters, numbers and special characters).
- Storing the master password in a SHA-256 hash file (`key.key`) to unlock the database.
- SQLite-based management of the password database.

## C Requirements
- **SQLite** with **SQLCipher** extension for encrypting the database.
- **OpenSSL** for SHA-256
- **xclip** (Linux) or **Windows Clipboard API** (Windows) for copying passwords to the clipboard.

## Python Requirements
- **cryptography** for AES encryption
- **pyperclip** for copying passwords to the clipboard.

## Notes:
- **Advanced Encryption Standard**: The python implementation uses AES for encryption instead of sqlcipher:  
  - **A new AES-encrypted database** is created to securely store passwords.
  - **The unencrypted version of the database** is deleted after encryption to ensure data protection.
  