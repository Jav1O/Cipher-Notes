import tempfile
import unittest
from pathlib import Path
from secrets import token_urlsafe
from unittest.mock import patch

import bcrypt

from auth import login, register
from models import AuthenticationError, ValidationError
from storage import Storage


class AuthenticationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(directory.cleanup)
        cls.storage = Storage(Path(directory.name) / "test.db")
        cls.storage.init_db()
        cls.password = token_urlsafe(24)
        cls.user = register(cls.storage, "Alice", cls.password)

    def test_registration_and_login(self):
        self.assertTrue(bcrypt.checkpw(self.password.encode(), self.user.password_hash))
        self.assertEqual(self.user.username, "alice")
        session = login(self.storage, "ALICE", self.password)
        self.assertEqual(session.user_id, self.user.id)
        self.assertNotIn(repr(session.dek), repr(session))

    def test_wrong_password_and_unknown_user_do_not_unlock_keys(self):
        with patch("auth.unlock_user_keys") as unlock:
            for username, password in (("alice", token_urlsafe(24)), ("unknown", self.password)):
                with self.subTest(username=username), self.assertRaises(AuthenticationError):
                    login(self.storage, username, password)
            unlock.assert_not_called()

    def test_same_password_uses_independent_salts(self):
        second_user = register(self.storage, "Bob", self.password)
        self.assertNotEqual(self.user.password_hash, second_user.password_hash)
        self.assertNotEqual(self.user.kdf_salt, second_user.kdf_salt)

    def test_duplicate_username(self):
        with self.assertRaises(ValidationError):
            register(self.storage, "ALICE", self.password)

    def test_invalid_inputs_and_utf8_byte_limit(self):
        inputs = (("ños", self.password), ("ok_name", ""), ("ok_name", "é" * 37))
        for username, password in inputs:
            with self.subTest(username=username), self.assertRaises(ValidationError):
                register(self.storage, username, password)
