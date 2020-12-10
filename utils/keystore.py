import json
from dataclasses import (
    asdict,
    dataclass,
    fields,
    field as dataclass_field
)
from secrets import randbits
from typing import Any, Dict, Union
from unicodedata import normalize
from uuid import uuid4

from utils.crypto import (
    AES_128_CTR,
    PBKDF2,
    scrypt,
    SHA256,
)

UNICODE_CONTROL_CHARS = list(range(0x00, 0x20)) + list(range(0x7F, 0xA0))

# https://github.com/ethereum/eth2.0-deposit-cli/blob/master/eth2deposit/key_handling/keystore.py
# Commit: b6f7ca9

hexdigits = set('0123456789abcdef')


def encode_bytes(obj: Union[str, Dict[str, Any]]) -> Union[bytes, str, Dict[str, Any]]:
    """
    Recursively encodes objects that contain hexstrings into objects that contain bytes.
    """
    if isinstance(obj, str) and all(c in hexdigits for c in obj):
        return bytes.fromhex(obj)
    elif isinstance(obj, dict):
        for key, value in obj.items():
            obj[key] = encode_bytes(value)
    return obj


class BytesDataclass:
    """
    BytesDataClasses are DataClass objects that automatically encode hexstrings into bytes,
    and have an `as_json` function that encodes bytes back into hexstrings.
    """

    def __post_init__(self) -> None:
        for field in fields(self):
            if field.type in (bytes, Dict[str, Any]):
                # Convert hexstring to bytes
                self.__setattr__(field.name, encode_bytes(self.__getattribute__(field.name)))

    def as_json(self) -> str:
        return json.dumps(asdict(self), default=lambda x: x.hex())


@dataclass
class KeystoreModule(BytesDataclass):
    function: str = ''
    params: Dict[str, Any] = dataclass_field(default_factory=dict)
    message: bytes = bytes()


@dataclass
class KeystoreCrypto(BytesDataclass):
    kdf: KeystoreModule = KeystoreModule()
    checksum: KeystoreModule = KeystoreModule()
    cipher: KeystoreModule = KeystoreModule()

    @classmethod
    def from_json(cls, json_dict: Dict[Any, Any]) -> 'KeystoreCrypto':
        kdf = KeystoreModule(**json_dict['kdf'])
        checksum = KeystoreModule(**json_dict['checksum'])
        cipher = KeystoreModule(**json_dict['cipher'])
        return cls(kdf=kdf, checksum=checksum, cipher=cipher)


@dataclass
class Keystore(BytesDataclass):
    """
    Implement an EIP 2335-compliant keystore. A keystore is a JSON file that
    stores an encrypted version of a private key under a user-supplied password.

    Ref: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2335.md
    """
    crypto: KeystoreCrypto = KeystoreCrypto()
    uuid: str = ''
    index: int = 0
    threshold: int = 0
    public_key: str = ''

    def kdf(self, **kwargs: Any) -> bytes:
        return scrypt(**kwargs) if 'scrypt' in self.crypto.kdf.function else PBKDF2(**kwargs)

    @classmethod
    def from_json(cls, json_dict: Dict[Any, Any]) -> 'Keystore':
        crypto = KeystoreCrypto.from_json(json_dict['crypto'])
        uuid = json_dict['uuid']
        index = json_dict['index']
        threshold = json_dict['threshold']
        return cls(crypto=crypto, uuid=uuid, index=index, threshold=threshold)

    @staticmethod
    def _process_password(password: str) -> bytes:
        """
        Encode password as NFKD UTF-8 as per:
        https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2335.md#password-requirements
        """
        password = normalize('NFKD', password)
        password = ''.join(c for c in password if ord(c) not in UNICODE_CONTROL_CHARS)
        return password.encode('UTF-8')

    @classmethod
    def encrypt(cls, *, secret: bytes, password: str, index: int, public_key: str, threshold: int,
                kdf_salt: bytes = randbits(256).to_bytes(32, 'big'),
                aes_iv: bytes = randbits(128).to_bytes(16, 'big')) -> 'Keystore':
        """
        Encrypt a secret (BLS SK) as an EIP 2335 Keystore.
        """
        keystore = cls()
        keystore.uuid = str(uuid4())
        keystore.index = index
        keystore.threshold = threshold
        keystore.public_key = public_key
        keystore.crypto.kdf.params['salt'] = kdf_salt
        decryption_key = keystore.kdf(
            password=cls._process_password(password),
            **keystore.crypto.kdf.params
        )
        keystore.crypto.cipher.params['iv'] = aes_iv
        cipher = AES_128_CTR(key=decryption_key[:16], **keystore.crypto.cipher.params)
        keystore.crypto.cipher.message = cipher.encrypt(secret)
        keystore.crypto.checksum.message = SHA256(decryption_key[16:32] + keystore.crypto.cipher.message)
        return keystore

    def decrypt(self, password: str) -> bytes:
        """
        Retrieve the secret (BLS SK) from the self keystore by decrypting it with `password`
        """
        decryption_key = self.kdf(
            password=self._process_password(password),
            **self.crypto.kdf.params
        )
        if SHA256(decryption_key[16:32] + self.crypto.cipher.message) != self.crypto.checksum.message:
            raise ValueError("Checksum message error")

        cipher = AES_128_CTR(key=decryption_key[:16], **self.crypto.cipher.params)
        return cipher.decrypt(self.crypto.cipher.message)


@dataclass
class Pbkdf2Keystore(Keystore):
    crypto: KeystoreCrypto = KeystoreCrypto(
        kdf=KeystoreModule(
            function='pbkdf2',
            params={
                'c': 2 ** 18,
                'dklen': 32,
                "prf": 'hmac-sha256'
            },
        ),
        checksum=KeystoreModule(
            function='sha256',
        ),
        cipher=KeystoreModule(
            function='aes-128-ctr',
        )
    )
