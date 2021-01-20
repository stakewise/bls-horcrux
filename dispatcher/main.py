from typing import Iterator, List, Tuple

from Crypto.PublicKey import RSA
from eth2deposit.utils.crypto import SHA256
from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy.orm import Session

from cli.crypto import rsa_verify
from . import crud, models, schemas
from .database import Base, SessionLocal, engine

Base.metadata.create_all(bind=engine)

app = FastAPI()


# Dependency
def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.post("/", response_model=schemas.Share)
def create_share(
    data: schemas.ShareCreate, db: Session = Depends(get_db)
) -> models.Share:
    try:
        ciphertext = bytes.fromhex(data.ciphertext)
        signature = bytes.fromhex(data.signature)
        rsa_public_key = RSA.import_key(data.sender_rsa_public_key)
        sender_rsa_public_key_hash = SHA256(
            data.sender_rsa_public_key.encode("ascii")
        ).hex()
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid sender RSA public key")

    if not rsa_verify(rsa_public_key, ciphertext, signature):
        raise HTTPException(status_code=400, detail="Invalid RSA signature")

    if (
        crud.get_share(
            db=db,
            sender_rsa_public_key_hash=sender_rsa_public_key_hash,
            recipient_rsa_public_key_hash=data.recipient_rsa_public_key_hash,
        )
        is not None
    ):
        raise HTTPException(
            status_code=400, detail="The data for the participant was already submitted"
        )

    return crud.create_share(
        db=db,
        recipient_rsa_public_key_hash=data.recipient_rsa_public_key_hash,
        sender_rsa_public_key_hash=sender_rsa_public_key_hash,
        enc_session_key=data.enc_session_key,
        ciphertext=data.ciphertext,
        tag=data.tag,
        nonce=data.nonce,
        signature=data.signature,
    )


@app.get("/{public_key_hash}/", response_model=List[schemas.Share])
def get_shares(
    public_key_hash: str, db: Session = Depends(get_db)
) -> List[Tuple[int, str, str, str, str, str, str]]:
    shared = crud.get_shares(db=db, public_key_hash=public_key_hash)
    return shared
