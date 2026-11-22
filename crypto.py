"""Cifrado autenticado AES-256-GCM con nonces de 96 bits."""

import logging
from os import urandom

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from models import IntegrityError, ValidationError

KEY_LENGTH = 32
NONCE_LENGTH = 12
TAG_LENGTH = 16
MAX_NONCE_ATTEMPTS = 16


def generate_dek() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def aesgcm_encrypt(
    key: bytes,
    data: bytes,
    aad: bytes,
    forbidden_nonces: set[bytes] | None = None,
) -> tuple[bytes, bytes]:
    if not isinstance(key, bytes) or len(key) != KEY_LENGTH:
        raise ValidationError("AES-256-GCM requiere una clave de 32 bytes.")

    for _ in range(MAX_NONCE_ATTEMPTS):
        nonce = urandom(NONCE_LENGTH)
        if forbidden_nonces and nonce in forbidden_nonces:
            logging.getLogger(__name__).warning("Colisión de nonce. Se genera otro.")
            continue
        return nonce, AESGCM(key).encrypt(nonce, data, aad)
    raise IntegrityError("No se pudo generar un nonce nuevo.")


def aesgcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    if (
        not isinstance(key, bytes)
        or len(key) != KEY_LENGTH
        or not isinstance(nonce, bytes)
        or len(nonce) != NONCE_LENGTH
        or not isinstance(ciphertext, bytes)
        or len(ciphertext) < TAG_LENGTH
    ):
        raise IntegrityError("El registro AES-GCM tiene un formato inválido.")

    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as error:
        raise IntegrityError("El tag de AES-GCM es inválido.") from error
