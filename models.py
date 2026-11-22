"""Registros de SQLite, sesión y errores compartidos."""

from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey


@dataclass(frozen=True)
class UserRecord:
    id: str
    username: str
    password_hash: bytes = field(repr=False)
    kdf_salt: bytes
    kdf_iterations: int
    dek_nonce: bytes
    encrypted_dek: bytes
    rsa_nonce: bytes
    encrypted_private_key: bytes
    public_key_der: bytes


@dataclass(frozen=True)
class NoteRecord:
    id: str
    owner_id: str
    format_version: int
    nonce: bytes
    ciphertext: bytes
    signature: bytes


@dataclass(frozen=True)
class Session:
    user_id: str
    username: str
    dek: bytes = field(repr=False)
    rsa_private_key: RSAPrivateKey = field(repr=False)


class CipherNotesError(Exception):
    """Error esperado que la consola puede presentar al usuario."""


class AuthenticationError(CipherNotesError):
    pass


class AuthorizationError(CipherNotesError):
    pass


class IntegrityError(CipherNotesError):
    pass


class SignatureValidationError(IntegrityError):
    pass


class NotFoundError(CipherNotesError):
    pass


class KeyUnlockError(CipherNotesError):
    pass


class ValidationError(CipherNotesError):
    pass


class StorageError(CipherNotesError):
    pass
