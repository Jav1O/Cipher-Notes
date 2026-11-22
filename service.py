"""Creación, consulta y verificación de notas pertenecientes a la sesión."""

import re
from dataclasses import replace
from uuid import uuid4

from crypto import NONCE_LENGTH, TAG_LENGTH, aesgcm_decrypt, aesgcm_encrypt
from formats import (
    FORMAT_VERSION,
    note_aad,
    note_plaintext_bytes,
    parse_note_plaintext,
    signed_note_bytes,
)
from models import (
    AuthorizationError,
    IntegrityError,
    NoteRecord,
    NotFoundError,
    Session,
    SignatureValidationError,
    ValidationError,
)
from signatures import sign_bytes, verify_bytes
from storage import Storage

NOTE_ID_PATTERN = re.compile(r"[0-9a-f]{32}")


def create_note(storage: Storage, session: Session, title: str, body: str) -> str:
    if not title.strip() or len(title) > 200:
        raise ValidationError("El título debe tener entre 1 y 200 caracteres.")
    if not body.strip() or len(body) > 20_000:
        raise ValidationError("El contenido debe tener entre 1 y 20 000 caracteres.")

    note_id = uuid4().hex
    plaintext = note_plaintext_bytes(title, body)
    aad = note_aad(session.user_id, note_id)

    def build_note(forbidden_nonces: set[bytes]) -> NoteRecord:
        nonce, ciphertext = aesgcm_encrypt(session.dek, plaintext, aad, forbidden_nonces)
        unsigned = NoteRecord(note_id, session.user_id, FORMAT_VERSION, nonce, ciphertext, b"")
        signature = sign_bytes(session.rsa_private_key, signed_note_bytes(unsigned))
        return replace(unsigned, signature=signature)

    storage.insert_note_with_unique_nonce(session.user_id, build_note)
    return note_id


def list_notes(storage: Storage, session: Session) -> list[NoteRecord]:
    return storage.list_notes(session.user_id)


def _get_note(storage: Storage, session: Session, note_id: str) -> NoteRecord:
    if NOTE_ID_PATTERN.fullmatch(note_id) is None:
        raise ValidationError("Introduce el ID completo de 32 caracteres que aparece en la lista.")
    note = storage.get_note_for_owner(note_id, session.user_id)
    if note is None:
        raise NotFoundError("No se encontró esa nota en tu cuenta.")
    if note.owner_id != session.user_id:
        raise AuthorizationError("La nota pertenece a otra cuenta.")
    if (
        note.format_version != FORMAT_VERSION
        or not isinstance(note.nonce, bytes)
        or len(note.nonce) != NONCE_LENGTH
        or not isinstance(note.ciphertext, bytes)
        or len(note.ciphertext) < TAG_LENGTH
    ):
        raise IntegrityError("El registro de la nota tiene un formato inválido.")
    return note


def _verify_signature(session: Session, note: NoteRecord) -> None:
    # Durante el login se verifica que esta pública coincide con la de la cuenta en SQLite.
    verify_bytes(session.rsa_private_key.public_key(), signed_note_bytes(note), note.signature)


def open_note(storage: Storage, session: Session, note_id: str) -> tuple[str, str]:
    note = _get_note(storage, session, note_id)
    _verify_signature(session, note)
    aad = note_aad(note.owner_id, note.id, note.format_version)
    plaintext = aesgcm_decrypt(session.dek, note.nonce, note.ciphertext, aad)
    return parse_note_plaintext(plaintext)


def verify_note_signature(storage: Storage, session: Session, note_id: str) -> bool:
    note = _get_note(storage, session, note_id)
    try:
        _verify_signature(session, note)
    except SignatureValidationError:
        return False
    return True
