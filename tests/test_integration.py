import os
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from secrets import token_urlsafe
from unittest.mock import patch
from uuid import uuid4

from auth import login, register
from crypto import generate_dek
from formats import signed_note_bytes
from models import IntegrityError, NotFoundError, SignatureValidationError
from service import create_note, list_notes, open_note, verify_note_signature
from signatures import serialize_private_key_der, sign_bytes
from storage import Storage


class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(directory.cleanup)
        cls.path = Path(directory.name) / "integration.db"
        cls.storage = Storage(cls.path)
        cls.storage.init_db()
        cls.password = token_urlsafe(24)
        register(cls.storage, "alice", cls.password)
        cls.alice = login(cls.storage, "alice", cls.password)
        bob_password = token_urlsafe(24)
        register(cls.storage, "bob", bob_password)
        cls.bob = login(cls.storage, "bob", bob_password)

    def _new_note(self):
        return create_note(self.storage, self.alice, "Título privado de prueba", "Contenido de prueba 🔐")

    def _saved_note(self, note_id):
        note = self.storage.get_note_for_owner(note_id, self.alice.user_id)
        self.assertIsNotNone(note)
        return note

    def _update(self, statement, parameters):
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute(statement, parameters)

    def test_persistence_signature_and_no_plaintext_in_database(self):
        note_id = self._new_note()
        reopened = Storage(self.path)
        reopened.init_db()
        session = login(reopened, "alice", self.password)
        self.assertTrue(verify_note_signature(reopened, session, note_id))
        title, body = open_note(reopened, session, note_id)
        self.assertEqual((title, body), ("Título privado de prueba", "Contenido de prueba 🔐"))
        stored = self.path.read_bytes()
        for secret in (
            title.encode(),
            body.encode(),
            b"privado de prueba",
            b"Contenido de prueba",
            self.password.encode(),
            session.dek,
            serialize_private_key_der(session.rsa_private_key),
        ):
            self.assertNotIn(secret, stored)

    def test_other_account_cannot_list_read_or_verify(self):
        note_id = self._new_note()
        self.assertNotIn(note_id, [note.id for note in list_notes(self.storage, self.bob)])
        for operation in (open_note, verify_note_signature):
            with self.assertRaises(NotFoundError):
                operation(self.storage, self.bob, note_id)

    def test_modified_signature_is_rejected(self):
        note_id = self._new_note()
        signature = self._saved_note(note_id).signature
        tampered = bytes([signature[0] ^ 1]) + signature[1:]
        self._update("UPDATE notes SET signature = ? WHERE id = ?", (tampered, note_id))
        self.assertFalse(verify_note_signature(self.storage, self.alice, note_id))
        with self.assertRaises(SignatureValidationError):
            open_note(self.storage, self.alice, note_id)

    def test_modified_ciphertext_fails_signature_check(self):
        note_id = self._new_note()
        ciphertext = self._saved_note(note_id).ciphertext
        tampered = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
        self._update("UPDATE notes SET ciphertext = ? WHERE id = ?", (tampered, note_id))
        with self.assertRaises(SignatureValidationError):
            open_note(self.storage, self.alice, note_id)

    def test_modified_tag_rejected_even_when_test_resigns_the_record(self):
        note_id = self._new_note()
        record = self._saved_note(note_id)
        changed = record.ciphertext[:-1] + bytes([record.ciphertext[-1] ^ 1])
        changed_record = replace(record, ciphertext=changed)
        signature = sign_bytes(self.alice.rsa_private_key, signed_note_bytes(changed_record))
        self._update(
            "UPDATE notes SET ciphertext = ?, signature = ? WHERE id = ?",
            (changed, signature, note_id),
        )
        self.assertTrue(verify_note_signature(self.storage, self.alice, note_id))
        with self.assertRaisesRegex(IntegrityError, "tag de AES-GCM"):
            open_note(self.storage, self.alice, note_id)

    def test_changed_id_and_owner_fail_verification(self):
        note_id = self._new_note()
        new_id = uuid4().hex
        self._update("UPDATE notes SET id = ? WHERE id = ?", (new_id, note_id))
        with self.assertRaises(SignatureValidationError):
            open_note(self.storage, self.alice, new_id)
        self._update("UPDATE notes SET owner_id = ? WHERE id = ?", (self.bob.user_id, new_id))
        with self.assertRaises(SignatureValidationError):
            open_note(self.storage, self.bob, new_id)

    def test_unknown_version_and_truncated_data_are_rejected(self):
        note_id = self._new_note()
        self._update("UPDATE notes SET format_version = ? WHERE id = ?", (2, note_id))
        with self.assertRaises(IntegrityError):
            open_note(self.storage, self.alice, note_id)
        self._update(
            "UPDATE notes SET format_version = ?, ciphertext = ? WHERE id = ?",
            (1, b"truncated", note_id),
        )
        with self.assertRaises(IntegrityError):
            open_note(self.storage, self.alice, note_id)

    def test_wrong_note_key_fails_after_signature_verification(self):
        note_id = self._new_note()
        wrong_session = replace(self.alice, dek=generate_dek())
        self.assertTrue(verify_note_signature(self.storage, wrong_session, note_id))
        with self.assertRaisesRegex(IntegrityError, "tag de AES-GCM"):
            open_note(self.storage, wrong_session, note_id)

    def test_repeated_nonce_is_discarded_before_encrypting(self):
        first = self._saved_note(self._new_note())
        fresh_nonce = os.urandom(12)
        with (
            patch("crypto.urandom", side_effect=[first.nonce, fresh_nonce]),
            self.assertLogs("crypto", level="WARNING"),
        ):
            second = self._saved_note(self._new_note())
        self.assertEqual(second.nonce, fresh_nonce)
        self.assertTrue(verify_note_signature(self.storage, self.alice, second.id))

    def test_concurrent_notes_cannot_reuse_the_same_nonce(self):
        first_nonce, second_nonce = os.urandom(12), os.urandom(12)
        with (
            ThreadPoolExecutor(max_workers=2) as pool,
            patch("crypto.urandom", side_effect=[first_nonce, first_nonce, second_nonce]),
            self.assertLogs("crypto", level="WARNING"),
        ):
            pending = [pool.submit(self._new_note) for _ in range(2)]
            note_ids = [future.result() for future in pending]
        self.assertEqual({self._saved_note(note_id).nonce for note_id in note_ids},
                         {first_nonce, second_nonce})

    def test_restoring_a_valid_record_is_not_detected(self):
        note_id = self._new_note()
        record = self._saved_note(note_id)
        self._update("DELETE FROM notes WHERE id = ?", (note_id,))
        self.storage.insert_note(record)
        self.assertTrue(verify_note_signature(self.storage, self.alice, note_id))
