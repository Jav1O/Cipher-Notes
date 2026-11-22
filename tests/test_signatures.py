import unittest

from models import SignatureValidationError
from signatures import (
    generate_rsa_keypair,
    load_private_key_der,
    load_public_key_der,
    serialize_private_key_der,
    serialize_public_key_der,
    sign_bytes,
    verify_bytes,
)


class SignatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key, cls.public_key = generate_rsa_keypair()

    def test_signature_survives_der_round_trip(self):
        private_key = load_private_key_der(serialize_private_key_der(self.private_key))
        public_key = load_public_key_der(serialize_public_key_der(self.public_key))
        message = b"Encrypted note record"
        verify_bytes(public_key, message, sign_bytes(private_key, message))

    def test_wrong_message_signature_and_public_key_are_rejected(self):
        message = b"Encrypted note record"
        signature = sign_bytes(self.private_key, message)
        tampered = bytes([signature[0] ^ 1]) + signature[1:]
        _, other_key = generate_rsa_keypair()
        cases = (
            (self.public_key, message + b"!", signature),
            (self.public_key, message, tampered),
            (other_key, message, signature),
        )
        for public_key, payload, candidate in cases:
            with self.assertRaises(SignatureValidationError):
                verify_bytes(public_key, payload, candidate)
