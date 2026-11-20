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
