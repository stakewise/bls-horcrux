from __future__ import annotations

from dataclasses import dataclass
from random import randint
from typing import Any, Dict, List, Tuple, cast

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Cipher._mode_eax import EaxMode
from Crypto.Hash import SHA256
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from eth2deposit.key_handling.keystore import Pbkdf2Keystore
from eth_typing.bls import BLSPubkey, BLSSignature
from py_ecc.bls.ciphersuites import G2ProofOfPossession as bls_pop
from py_ecc.bls.g2_primitives import G2_to_signature, signature_to_G2
from py_ecc.optimized_bls12_381.optimized_curve import Z2, add, curve_order, multiply
from py_ecc.utils import prime_field_inv

PRIME = curve_order
DEFAULT_INDEX = 0
DEFAULT_THRESHOLD = 0
DEFAULT_SHARED_PUBLIC_KEY = ""
DEFAULT_SHARED_WITHDRAWAL_CREDS = ""


@dataclass
class HorcruxPbkdf2Keystore(Pbkdf2Keystore):  # type: ignore
    """Used for encrypting the private key and storing it in the keystore file."""

    index: int = DEFAULT_INDEX
    threshold: int = DEFAULT_THRESHOLD
    shared_public_key: str = DEFAULT_SHARED_PUBLIC_KEY
    shared_withdrawal_credentials: str = DEFAULT_SHARED_WITHDRAWAL_CREDS

    @classmethod
    def create_from_private_key(
        cls,
        *,
        private_key: int,
        password: str,
        index: int = DEFAULT_INDEX,
        threshold: int = DEFAULT_THRESHOLD,
        shared_public_key: str = DEFAULT_SHARED_PUBLIC_KEY,
        shared_withdrawal_credentials: str = DEFAULT_SHARED_WITHDRAWAL_CREDS
    ) -> HorcruxPbkdf2Keystore:
        parent_keystore = super().encrypt(
            secret=private_key.to_bytes(length=32, byteorder="big"), password=password
        )
        # Ignored because mypy fails to detect parent dataclass keyword arguments
        return cls(  # type: ignore
            index=index,
            threshold=threshold,
            shared_public_key=shared_public_key,
            shared_withdrawal_credentials=shared_withdrawal_credentials,
            # parent dataclass keyword arguments
            crypto=parent_keystore.crypto,
            description=parent_keystore.description,
            pubkey=parent_keystore.pubkey,
            path=parent_keystore.path,
            uuid=parent_keystore.uuid,
            version=parent_keystore.version,
        )

    @classmethod
    def create_from_json(cls, json_dict: Dict[Any, Any]) -> HorcruxPbkdf2Keystore:
        parent_keystore = super().from_json(json_dict)
        # Ignored because mypy fails to detect parent dataclass keyword arguments
        return cls(  # type: ignore
            index=json_dict["index"],
            threshold=json_dict["threshold"],
            shared_public_key=json_dict["shared_public_key"],
            shared_withdrawal_credentials=json_dict["shared_withdrawal_credentials"],
            # parent dataclass keyword arguments
            crypto=parent_keystore.crypto,
            description=parent_keystore.description,
            pubkey=parent_keystore.pubkey,
            path=parent_keystore.path,
            uuid=parent_keystore.uuid,
            version=parent_keystore.version,
        )


def get_polynomial_points(coefficients: List[int], num_points: int) -> List[int]:
    """Calculates polynomial points."""
    points = []
    for x in range(1, num_points + 1):
        # start with x=1 and calculate the value of y
        y = coefficients[0]
        # calculate each term and add it to y, using modular math
        for i in range(1, len(coefficients)):
            exponentiation = (x ** i) % PRIME
            term = (coefficients[i] * exponentiation) % PRIME
            y = (y + term) % PRIME
        # add the point to the list of points
        points.append(y)
    return points


def get_bls_secret_shares(
    total: int, threshold: int
) -> Tuple[BLSPubkey, List[BLSPubkey], List[int]]:
    """Generates Shamir's secrets for the BLS keypair."""
    coefficients = [randint(0, PRIME - 1) for _ in range(threshold)]
    private_key_secrets = get_polynomial_points(coefficients, total)
    public_key_secrets = [
        bls_pop.SkToPk(private_key) for private_key in private_key_secrets
    ]
    return bls_pop.SkToPk(coefficients[0]), public_key_secrets, private_key_secrets


def rsa_encrypt(
    recipient_public_key: RsaKey, data: str
) -> Tuple[bytes, bytes, bytes, bytes]:
    """Encrypts data with rsa public key."""
    cipher_rsa = PKCS1_OAEP.new(recipient_public_key)
    session_key = get_random_bytes(32)

    # Encrypt the session key with the public RSA key
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = cast(EaxMode, AES.new(session_key, AES.MODE_EAX))
    ciphertext, tag = cipher_aes.encrypt_and_digest(data.encode("utf-8"))
    return enc_session_key, cipher_aes.nonce, tag, ciphertext


def rsa_sign(sender_private_key: RsaKey, ciphertext: bytes) -> bytes:
    """Signs ciphertext with rsa private key."""
    return pkcs1_15.new(sender_private_key).sign(SHA256.new(ciphertext))


def rsa_verify(sender_public_key: RsaKey, ciphertext: bytes, signature: bytes) -> bool:
    """Verifies ciphertext RSA signature."""
    try:
        pkcs1_15.new(sender_public_key).verify(SHA256.new(ciphertext), signature)
        return True
    except (ValueError, TypeError):
        return False


def rsa_decrypt(
    private_key: RsaKey,
    enc_session_key: bytes,
    nonce: bytes,
    tag: bytes,
    ciphertext: bytes,
) -> str:
    """Decrypts data with rsa private key."""
    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = cast(EaxMode, AES.new(session_key, AES.MODE_EAX, nonce))
    return cipher_aes.decrypt_and_verify(ciphertext, tag).decode("ascii")


def reconstruct_shared_bls_signature(
    signatures: Dict[int, BLSSignature]
) -> BLSSignature:
    """
    Reconstructs shared BLS private key signature.
    Copied from https://github.com/dankrad/python-ibft/blob/master/bls_threshold.py
    """
    r = Z2
    for i, sig in signatures.items():
        sig_point = signature_to_G2(sig)
        coef = 1
        for j in signatures:
            if j != i:
                coef = -coef * (j + 1) * prime_field_inv(i - j, PRIME) % PRIME
        r = add(r, multiply(sig_point, coef))
    return G2_to_signature(r)
