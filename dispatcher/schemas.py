from pydantic import BaseModel


class Share(BaseModel):
    enc_session_key: str
    ciphertext: str
    tag: str
    nonce: str

    class Config:
        orm_mode = True


class ShareCreate(Share):
    authentication_key: str
    sender_rsa_public_key_hash: str
    recipient_rsa_public_key_hash: str


class SharesFetch(BaseModel):
    authentication_key: str
    public_key_hash: str


class Health(BaseModel):
    status: str
