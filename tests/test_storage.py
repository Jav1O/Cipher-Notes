import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

from models import NoteRecord, StorageError, UserRecord, ValidationError
from storage import Storage


class StorageTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "test.db"
        self.storage = Storage(self.path)
        self.storage.init_db()

    def test_user_survives_new_storage_and_duplicate_is_rejected(self):
        user = UserRecord(uuid4().hex, "alice", b"", b"", 1, b"", b"", b"", b"", b"")
        self.storage.create_user(user)
        reopened = Storage(self.path)
        reopened.init_db()
        self.assertEqual(reopened.get_user_by_username("alice"), user)
        with self.assertRaises(ValidationError):
            reopened.create_user(replace(user, id=uuid4().hex))

    def test_foreign_key_and_nonce_uniqueness(self):
        note = NoteRecord(uuid4().hex, uuid4().hex, 1, os.urandom(12), b"", b"")
        with self.assertRaises(StorageError):
            self.storage.insert_note(note)
        self.storage.create_user(
            UserRecord(note.owner_id, "alice", b"", b"", 1, b"", b"", b"", b"", b"")
        )
        self.storage.insert_note(note)
        with self.assertRaises(StorageError):
            self.storage.insert_note(replace(note, id=uuid4().hex))
        self.assertEqual(self.storage.list_notes(note.owner_id), [note])
