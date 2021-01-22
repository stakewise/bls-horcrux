from sqlalchemy import Column, Integer, String

from .database import Base


class Share(Base):
    __tablename__ = "shares"

    id = Column(Integer, primary_key=True, index=True)
    recipient_rsa_public_key = Column(String)
    sender_rsa_public_key = Column(String)
    enc_session_key = Column(String)
    ciphertext = Column(String)
    tag = Column(String)
    nonce = Column(String)
    signature = Column(String)
