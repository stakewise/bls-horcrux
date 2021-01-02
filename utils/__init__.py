from dataclasses import dataclass
from random import randint
from typing import Tuple, List, Dict, Any

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Random import get_random_bytes
from eth2deposit.key_handling.keystore import Keystore
from eth2deposit.key_handling.keystore import Pbkdf2Keystore
from eth_typing import BLSPubkey
from py_ecc import optimized_bls12_381
from py_ecc.bls import G2ProofOfPossession as bls_pop

PRIME = optimized_bls12_381.curve_order


@dataclass
class HorcruxPbkdf2Keystore(Pbkdf2Keystore):
    index: int = 0
    threshold: int = 0
    shared_public_key: str = ''
    shared_withdrawal_credentials: str = ''

    @classmethod
    def encrypt(cls, *, secret: bytes, password: str, **kwargs) -> 'Keystore':
        keystore = super(Pbkdf2Keystore, cls).encrypt(secret=secret, password=password)
        keystore.index = kwargs.pop('index', 0)
        keystore.threshold = kwargs.pop('threshold', 0)
        keystore.shared_public_key = kwargs.pop('shared_public_key', '')

        return keystore

    @classmethod
    def from_json(cls, json_dict: Dict[Any, Any]) -> 'Keystore':
        keystore = super(Pbkdf2Keystore, cls).from_json(json_dict)
        keystore.index = json_dict['index']
        keystore.threshold = json_dict['threshold']
        keystore.shared_public_key = json_dict['shared_public_key']

        return keystore


def get_polynomial_points(coefficients, num_points) -> List[int]:
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


def get_bls_secret_shares(total: int, threshold: int) -> Tuple[BLSPubkey, List[BLSPubkey], List[int]]:
    """Generates Shamir's secrets for the BLS keypair."""
    coefficients = [randint(0, PRIME - 1) for _ in range(threshold)]
    private_key_secrets = get_polynomial_points(coefficients, total)
    public_key_secrets = [bls_pop.SkToPk(private_key) for private_key in private_key_secrets]
    return bls_pop.SkToPk(coefficients[0]), public_key_secrets, private_key_secrets


def rsa_encrypt(recipient_public_key: RsaKey, data: str) -> Tuple[bytes, bytes, bytes, bytes]:
    """Encrypts data with rsa public key."""
    cipher_rsa = PKCS1_OAEP.new(recipient_public_key)
    session_key = get_random_bytes(32)

    # Encrypt the session key with the public RSA key
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data.encode('utf-8'))
    return enc_session_key, cipher_aes.nonce, tag, ciphertext


def rsa_decrypt(private_key: RsaKey, enc_session_key: bytes, nonce: bytes, tag: bytes, ciphertext: bytes) -> str:
    """Decrypts data with rsa private key."""
    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    return cipher_aes.decrypt_and_verify(ciphertext, tag).decode('ascii')


def create_keystore(
        private_key: int,
        shared_public_key: str,
        index: int,
        threshold: int,
        password: str) -> 'Keystore':
    """:returns new keystore with one key-pair."""
    return HorcruxPbkdf2Keystore.encrypt(
        secret=private_key.to_bytes(length=32, byteorder='big'),
        password=password,
        index=index,
        threshold=threshold,
        shared_public_key=shared_public_key
    )
