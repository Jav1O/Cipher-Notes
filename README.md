# CipherNotes

**CipherNotes** is a Python application for storing private notes securely on a local device. It combines encrypted storage, password-based authentication and digital signatures to protect note contents and detect unauthorized modifications.

The application uses a simple command-line interface and stores its data in a local SQLite database.

## Features

- **User accounts:** register and sign in with passwords protected using bcrypt.
- **Encrypted notes:** create, list and read personal notes. Note titles and contents are encrypted before being saved.
- **Integrity protection:** AES-256-GCM detects changes to encrypted notes and rejects invalid data.
- **Digital signatures:** RSA-PSS with SHA-256 signs note records and allows their signatures to be verified.
- **Protected keys:** sensitive encryption and signing keys are stored encrypted rather than in plaintext.

## How it works

1. **Registration:** CipherNotes stores a salted bcrypt password hash, generates the user's encryption and signing keys, and protects the secret keys with a key derived from the password.
2. **Login:** the password is verified using bcrypt. PBKDF2-HMAC-SHA-256 derives a key that unlocks the user's protected keys.
3. **Saving a note:** the title and content are encrypted with AES-256-GCM and a fresh nonce. The encrypted record is signed using the user's RSA private key and saved in SQLite.
4. **Opening a note:** the application checks that the note belongs to the signed-in user, verifies its RSA signature, and decrypts it only if the AES-GCM authentication check succeeds.

## Cryptography

| Purpose | Technology |
| --- | --- |
| Password hashing | bcrypt |
| Password-based key derivation | PBKDF2-HMAC-SHA-256 |
| Note encryption and authentication | AES-256-GCM |
| Digital signatures | RSA-PSS with SHA-256 |
| Local data storage | SQLite |

Passwords are never stored in plaintext. A separate password-derived key protects the note-encryption key and RSA private signing key. AES-GCM uses fresh nonces for encryption, and signature verification uses the corresponding RSA public key.

## Security considerations

CipherNotes checks credentials, note ownership, authentication tags and signatures before returning private content. If a password is incorrect or encrypted data or a signature has been modified, the operation is rejected.

The application protects stored note contents but does not claim to protect against malware or a compromised device. Digital signatures are linked to local user accounts; they are not a substitute for identity verification through a certificate authority.

## Tech stack

- **Python** — application logic and command-line interface
- **cryptography** — AES-GCM, PBKDF2 and RSA signatures
- **bcrypt** — password hashing and verification
- **SQLite** — local persistence

## Run on Windows

Use CPython 3.12. Open PowerShell in the repository folder, where you can see `main.py` and `requirements.txt`. Run these commands one at a time.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py
```

On Linux or macOS with Python 3.12, use the following commands.

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python main.py
```

In the Spanish console menu, choose `1` to register and `2` to sign in. A username uses 3–32 ASCII letters, digits or underscores. A password uses at least 12 characters and at most 72 bytes in UTF-8. Use a unique passphrase for your account. The terminal hides password input.

After signing in, choose `1` to create a note. Enter a title, type the body and enter a single period on its own line to finish. Choose `2` to list notes, `3` to read a note by its full ID or `4` to check its signature. Choose `5` to sign out. Restarting CipherNotes leaves your account and notes available in the local database at `.local/ciphernotes.db`.

## Run the tests

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

On Linux or macOS, run `.venv/bin/python -m unittest discover -s tests -v`. Use the automated tests to demonstrate altered signatures and GCM tags. They generate temporary data and leave your local notes alone.

## Implementation details

- bcrypt uses cost 12 and its own salt. PBKDF2-HMAC-SHA-256 uses a separate, random 16-byte salt, 600,000 iterations and a 32-byte output.
- AES-256-GCM uses 12-byte nonces and 16-byte tags. Each account has a random AES key for its notes. The password-derived key wraps the notes key and the RSA private key in two AES-GCM operations with distinct nonces and AAD.
- Note AAD binds the format version, account ID and note ID. SQLite enforces nonce uniqueness per account. A write transaction checks existing nonces and discards a collision before encrypting.
- RSA uses a 2048-bit key, public exponent 65537, PSS with MGF1/SHA-256 and the maximum PSS salt length for those parameters. The signature covers the note metadata, nonce and ciphertext including its tag.
- The local account binds the RSA public key to the user's protected private key. The database can be deleted or rolled back to an earlier valid copy without detection. Forgotten passwords cannot be recovered in this version.
