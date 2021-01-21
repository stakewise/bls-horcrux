from pydantic import BaseModel


class Share(BaseModel):
    enc_session_key: str
    ciphertext: str
    tag: str
    nonce: str
    signature: str

    class Config:
        orm_mode = True


class ShareCreate(Share):
    sender_rsa_public_key: str
    recipient_rsa_public_key_hash: str
