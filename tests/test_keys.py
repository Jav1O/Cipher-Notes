import os
import unittest
from dataclasses import replace
from secrets import token_urlsafe
from uuid import uuid4

from keys import KDF_ITERATIONS, derive_kek, generate_protected_user_keys, unlock_user_keys
from models import KeyUnlockError, UserRecord
from signatures import generate_rsa_keypair, serialize_public_key_der


class KeyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password = token_urlsafe(24)
        user_id = uuid4().hex
        protected_keys = generate_protected_user_keys(user_id, cls.password)
        cls.user = UserRecord(user_id, "alice", b"", **protected_keys)

    def test_kek_is_deterministic_but_depends_on_salt(self):
        salt = os.urandom(16)
        kek = derive_kek(self.password, salt, KDF_ITERATIONS)
        self.assertEqual(len(kek), 32)
        self.assertEqual(kek, derive_kek(self.password, salt, KDF_ITERATIONS))
        self.assertNotEqual(kek, derive_kek(self.password, os.urandom(16), KDF_ITERATIONS))

    def test_unlock_returns_matching_keys_and_wraps_use_distinct_nonces(self):
        dek, private_key = unlock_user_keys(self.user, self.password)
        self.assertEqual(len(dek), 32)
        self.assertEqual(serialize_public_key_der(private_key.public_key()), self.user.public_key_der)
        self.assertNotEqual(self.user.dek_nonce, self.user.rsa_nonce)

    def test_modified_protected_keys_are_rejected(self):
        for field in ("encrypted_dek", "encrypted_private_key"):
            original = getattr(self.user, field)
            changed = bytes([original[0] ^ 1]) + original[1:]
            with self.subTest(field=field), self.assertRaises(KeyUnlockError):
                unlock_user_keys(replace(self.user, **{field: changed}), self.password)

    def test_substituted_public_key_is_rejected(self):
        _, unrelated = generate_rsa_keypair()
        modified = replace(self.user, public_key_der=serialize_public_key_der(unrelated))
        with self.assertRaises(KeyUnlockError):
            unlock_user_keys(modified, self.password)
