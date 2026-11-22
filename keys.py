"""Derivación de la KEK y protección de los secretos de cada cuenta."""

import os
from typing import TypedDict

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from crypto import KEY_LENGTH, aesgcm_decrypt, aesgcm_encrypt, generate_dek
from formats import wrap_aad
from models import IntegrityError, KeyUnlockError, UserRecord
from signatures import (
    generate_rsa_keypair,
    load_private_key_der,
    serialize_private_key_der,
    serialize_public_key_der,
)

KDF_ITERATIONS = 600_000
SALT_LENGTH = 16


class ProtectedUserKeys(TypedDict):
    kdf_salt: bytes
    kdf_iterations: int
    dek_nonce: bytes
    encrypted_dek: bytes
    rsa_nonce: bytes
    encrypted_private_key: bytes
    public_key_der: bytes


def derive_kek(password: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=KEY_LENGTH, salt=salt, iterations=iterations
    )
    return kdf.derive(password.encode("utf-8"))


def generate_protected_user_keys(user_id: str, password: str) -> ProtectedUserKeys:
    salt = os.urandom(SALT_LENGTH)
    kek = derive_kek(password, salt, KDF_ITERATIONS)
    private_key, public_key = generate_rsa_keypair()
    dek_nonce, encrypted_dek = aesgcm_encrypt(
        kek, generate_dek(), wrap_aad(user_id, "notes-dek")
    )
    rsa_nonce, encrypted_private_key = aesgcm_encrypt(
        kek,
        serialize_private_key_der(private_key),
        wrap_aad(user_id, "rsa-private"),
        forbidden_nonces={dek_nonce},
    )
    return {
        "kdf_salt": salt,
        "kdf_iterations": KDF_ITERATIONS,
        "dek_nonce": dek_nonce,
        "encrypted_dek": encrypted_dek,
        "rsa_nonce": rsa_nonce,
        "encrypted_private_key": encrypted_private_key,
        "public_key_der": serialize_public_key_der(public_key),
    }


def unlock_user_keys(user: UserRecord, password: str) -> tuple[bytes, RSAPrivateKey]:
    if (
        not isinstance(user.kdf_salt, bytes)
        or len(user.kdf_salt) != SALT_LENGTH
        or user.kdf_iterations != KDF_ITERATIONS
        or user.dek_nonce == user.rsa_nonce
    ):
        raise KeyUnlockError("Los parámetros de las claves protegidas son inválidos.")

    kek = derive_kek(password, user.kdf_salt, user.kdf_iterations)
    try:
        dek = aesgcm_decrypt(
            kek, user.dek_nonce, user.encrypted_dek, wrap_aad(user.id, "notes-dek")
        )
        private_key_der = aesgcm_decrypt(
            kek, user.rsa_nonce, user.encrypted_private_key, wrap_aad(user.id, "rsa-private")
        )
        private_key = load_private_key_der(private_key_der)
    except IntegrityError as error:
        raise KeyUnlockError("No se pudieron desbloquear las claves de la cuenta.") from error

    public_key_der = serialize_public_key_der(private_key.public_key())
    if len(dek) != KEY_LENGTH or public_key_der != user.public_key_der:
        raise KeyUnlockError("Las claves de la cuenta no coinciden.")
    return dek, private_key
