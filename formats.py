"""Formato canónico de notas, AAD y registros firmados."""

import base64
import json

from models import IntegrityError, NoteRecord

FORMAT_VERSION = 1


def canonical_bytes(obj: dict) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def note_plaintext_bytes(title: str, body: str) -> bytes:
    return canonical_bytes({"title": title, "body": body})


def parse_note_plaintext(raw: bytes) -> tuple[str, str]:
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise IntegrityError("El contenido de la nota tiene un formato inválido.") from error

    if (
        not isinstance(obj, dict)
        or obj.keys() != {"title", "body"}
        or not all(isinstance(value, str) for value in obj.values())
        or canonical_bytes(obj) != raw
    ):
        raise IntegrityError("El contenido de la nota tiene un formato inválido.")
    return obj["title"], obj["body"]


def note_aad(owner_id: str, note_id: str, version: int = FORMAT_VERSION) -> bytes:
    return canonical_bytes(
        {
            "kind": "ciphernotes-note",
            "version": version,
            "owner_id": owner_id,
            "note_id": note_id,
        }
    )


def wrap_aad(user_id: str, purpose: str, version: int = FORMAT_VERSION) -> bytes:
    return canonical_bytes(
        {
            "kind": "ciphernotes-key-wrap",
            "version": version,
            "user_id": user_id,
            "purpose": purpose,
        }
    )


def signed_note_bytes(note: NoteRecord) -> bytes:
    return canonical_bytes(
        {
            "kind": "ciphernotes-signed-note",
            "version": note.format_version,
            "owner_id": note.owner_id,
            "note_id": note.id,
            "nonce": base64.b64encode(note.nonce).decode("ascii"),
            "ciphertext": base64.b64encode(note.ciphertext).decode("ascii"),
        }
    )
