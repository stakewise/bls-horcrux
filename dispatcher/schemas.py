from pydantic import BaseModel


class Share(BaseModel):
    sender_rsa_public_key: str
    enc_session_key: str
    ciphertext: str
    tag: str
    nonce: str
    signature: str

    class Config:
        orm_mode = True


class ShareCreate(Share):
    authentication_key: str
    recipient_rsa_public_key: str


class SharesFetch(BaseModel):
    authentication_key: str
    rsa_public_key: str


class Health(BaseModel):
    status: str
