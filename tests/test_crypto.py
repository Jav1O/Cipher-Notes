import unittest

from crypto import aesgcm_decrypt, aesgcm_encrypt, generate_dek
from formats import canonical_bytes, note_aad, note_plaintext_bytes, parse_note_plaintext
from models import IntegrityError


class CryptoTests(unittest.TestCase):
    def test_round_trip_with_utf8(self):
        key = generate_dek()
        payload = note_plaintext_bytes("Álgebra", "Criptografía 🔐")
        aad = note_aad("owner", "note")
        nonce, ciphertext = aesgcm_encrypt(key, payload, aad)
        self.assertEqual(len(nonce), 12)
        self.assertEqual(len(ciphertext), len(payload) + 16)
        self.assertEqual(
            parse_note_plaintext(aesgcm_decrypt(key, nonce, ciphertext, aad)),
            ("Álgebra", "Criptografía 🔐"),
        )

    def test_gcm_rejects_changed_ciphertext_tag_nonce_aad_and_key(self):
        key = generate_dek()
        aad = note_aad("owner", "note")
        nonce, ciphertext = aesgcm_encrypt(key, b"demo", aad)
        cases = {
            "ciphertext": (key, nonce, bytes([ciphertext[0] ^ 1]) + ciphertext[1:], aad),
            "tag": (key, nonce, ciphertext[:-1] + bytes([ciphertext[-1] ^ 1]), aad),
            "nonce": (key, bytes([nonce[0] ^ 1]) + nonce[1:], ciphertext, aad),
            "aad": (key, nonce, ciphertext, note_aad("other", "note")),
            "key": (generate_dek(), nonce, ciphertext, aad),
            "truncated": (key, nonce, ciphertext[:15], aad),
        }
        for name, args in cases.items():
            with self.subTest(name=name), self.assertRaises(IntegrityError):
                aesgcm_decrypt(*args)

    def test_canonical_format_and_rejection_of_bad_json(self):
        self.assertEqual(canonical_bytes({"z": 1, "a": 2}), b'{"a":2,"z":1}')
        for raw in (b"{", b'{"body":42,"title":"a"}', b'{"title":"a", "body":"b"}'):
            with self.subTest(raw=raw), self.assertRaises(IntegrityError):
                parse_note_plaintext(raw)
