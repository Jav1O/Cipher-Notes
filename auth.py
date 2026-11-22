"""Registro y autenticación de cuentas."""

import re
from uuid import uuid4

import bcrypt

from keys import generate_protected_user_keys, unlock_user_keys
from models import AuthenticationError, Session, UserRecord, ValidationError
from storage import Storage

BCRYPT_COST = 12
BCRYPT_PREFIX = f"$2b${BCRYPT_COST:02d}$".encode("ascii")
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_BYTES = 72
USERNAME_PATTERN = re.compile(r"[a-zA-Z0-9_]{3,32}")


def _validate_credentials(username: str, password: str) -> tuple[str, bytes]:
    if USERNAME_PATTERN.fullmatch(username) is None:
        raise ValidationError("Usa entre 3 y 32 letras ASCII, números o guiones bajos.")
    try:
        encoded_password = password.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValidationError("La contraseña no se puede codificar en UTF-8.") from error
    if len(password) < MIN_PASSWORD_LENGTH or len(encoded_password) > MAX_PASSWORD_BYTES:
        raise ValidationError("La contraseña debe tener al menos 12 caracteres y hasta 72 bytes UTF-8.")
    return username.lower(), encoded_password


def register(storage: Storage, username: str, password: str) -> UserRecord:
    username, encoded_password = _validate_credentials(username, password)
    if storage.get_user_by_username(username) is not None:
        raise ValidationError("Ese nombre de usuario ya existe.")

    user_id = uuid4().hex
    password_hash = bcrypt.hashpw(encoded_password, bcrypt.gensalt(rounds=BCRYPT_COST))
    protected_keys = generate_protected_user_keys(user_id, password)
    user = UserRecord(user_id, username, password_hash, **protected_keys)
    storage.create_user(user)
    return user


def login(storage: Storage, username: str, password: str) -> Session:
    try:
        username, encoded_password = _validate_credentials(username, password)
        user = storage.get_user_by_username(username)
        if (
            user is None
            or not isinstance(user.password_hash, bytes)
            or len(user.password_hash) != 60
            or not user.password_hash.startswith(BCRYPT_PREFIX)
            or not bcrypt.checkpw(encoded_password, user.password_hash)
        ):
            raise AuthenticationError("Usuario o contraseña incorrectos.")
    except (ValidationError, TypeError, ValueError) as error:
        raise AuthenticationError("Usuario o contraseña incorrectos.") from error

    dek, private_key = unlock_user_keys(user, password)
    return Session(user.id, user.username, dek, private_key)
