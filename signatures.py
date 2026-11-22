"""Claves RSA de 2048 bits y firmas PSS con SHA-256."""

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from models import IntegrityError, SignatureValidationError

RSA_BITS = 2048
RSA_EXPONENT = 65537
SIGNATURE_LENGTH = RSA_BITS // 8
PSS_PADDING = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
)


def generate_rsa_keypair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    private_key = rsa.generate_private_key(public_exponent=RSA_EXPONENT, key_size=RSA_BITS)
    return private_key, private_key.public_key()


def serialize_private_key_der(private_key: rsa.RSAPrivateKey) -> bytes:
    return private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def serialize_public_key_der(public_key: rsa.RSAPublicKey) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_private_key_der(raw: bytes) -> rsa.RSAPrivateKey:
    try:
        key = serialization.load_der_private_key(raw, password=None)
    except (TypeError, ValueError, UnsupportedAlgorithm) as error:
        raise IntegrityError("La clave privada de la cuenta es inválida.") from error
    if not isinstance(key, rsa.RSAPrivateKey):
        raise IntegrityError("La clave privada de la cuenta no es RSA.")
    _validate_public_key(key.public_key())
    return key


def load_public_key_der(raw: bytes) -> rsa.RSAPublicKey:
    try:
        key = serialization.load_der_public_key(raw)
    except (TypeError, ValueError, UnsupportedAlgorithm) as error:
        raise IntegrityError("La clave pública de la cuenta es inválida.") from error
    if not isinstance(key, rsa.RSAPublicKey):
        raise IntegrityError("La clave pública de la cuenta no es RSA.")
    _validate_public_key(key)
    return key


def _validate_public_key(key: rsa.RSAPublicKey) -> None:
    if key.key_size != RSA_BITS or key.public_numbers().e != RSA_EXPONENT:
        raise IntegrityError("La clave RSA tiene parámetros inesperados.")


def sign_bytes(private_key: rsa.RSAPrivateKey, message: bytes) -> bytes:
    return private_key.sign(message, PSS_PADDING, hashes.SHA256())


def verify_bytes(public_key: rsa.RSAPublicKey, message: bytes, signature: bytes) -> None:
    if not isinstance(signature, bytes) or len(signature) != SIGNATURE_LENGTH:
        raise SignatureValidationError("La firma RSA-PSS es inválida.")
    try:
        public_key.verify(signature, message, PSS_PADDING, hashes.SHA256())
    except InvalidSignature as error:
        raise SignatureValidationError("La firma RSA-PSS es inválida.") from error
