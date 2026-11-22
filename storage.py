"""Persistencia local mediante SQLite."""

import sqlite3
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from dataclasses import astuple
from pathlib import Path

from models import NoteRecord, StorageError, UserRecord, ValidationError

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT NOT NULL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash BLOB NOT NULL,
    kdf_salt BLOB NOT NULL,
    kdf_iterations INTEGER NOT NULL,
    dek_nonce BLOB NOT NULL,
    encrypted_dek BLOB NOT NULL,
    rsa_nonce BLOB NOT NULL,
    encrypted_private_key BLOB NOT NULL,
    public_key_der BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS notes (
    id TEXT NOT NULL PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES users(id),
    format_version INTEGER NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    signature BLOB NOT NULL,
    UNIQUE(owner_id, nonce)
);
CREATE INDEX IF NOT EXISTS notes_owner_idx ON notes(owner_id);
"""


class Storage:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        try:
            with closing(sqlite3.connect(self.path)) as connection:
                connection.row_factory = sqlite3.Row
                connection.execute("PRAGMA foreign_keys = ON")
                with connection:
                    yield connection
        except sqlite3.Error as error:
            raise StorageError("No se pudo completar la operación en la base de datos.") from error

    def init_db(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError as error:
            raise StorageError("No se pudo crear la carpeta de datos.") from error

        with self._connect() as connection:
            connection.executescript("BEGIN;\n" + SCHEMA + "\nCOMMIT;")

    def create_user(self, user: UserRecord) -> None:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO users (
                    id, username, password_hash, kdf_salt, kdf_iterations, dek_nonce,
                    encrypted_dek, rsa_nonce, encrypted_private_key, public_key_der
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(username) DO NOTHING
                """,
                astuple(user),
            )
            if cursor.rowcount == 0:
                raise ValidationError("Ese nombre de usuario ya existe.")

    def get_user_by_username(self, username: str) -> UserRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
        return UserRecord(**row) if row is not None else None

    def insert_note(self, note: NoteRecord) -> None:
        with self._connect() as connection:
            self._write_note(connection, note)

    def insert_note_with_unique_nonce(
        self, owner_id: str, build_note: Callable[[set[bytes]], NoteRecord]
    ) -> None:
        with self._connect() as connection:
            # El bloqueo de escritura dura hasta insertar la nota o revertir la operación.
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT nonce FROM notes WHERE owner_id = ?", (owner_id,)
            )
            note = build_note({row["nonce"] for row in rows})
            self._write_note(connection, note)

    @staticmethod
    def _write_note(connection: sqlite3.Connection, note: NoteRecord) -> None:
        connection.execute(
            """
            INSERT INTO notes (id, owner_id, format_version, nonce, ciphertext, signature)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            astuple(note),
        )

    def list_notes(self, owner_id: str) -> list[NoteRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM notes WHERE owner_id = ? ORDER BY rowid", (owner_id,)
            ).fetchall()
        return [NoteRecord(**row) for row in rows]

    def get_note_for_owner(self, note_id: str, owner_id: str) -> NoteRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM notes WHERE id = ? AND owner_id = ?", (note_id, owner_id)
            ).fetchone()
        return NoteRecord(**row) if row is not None else None
