import os
from typing import Iterator, List, Tuple

from Crypto.PublicKey import RSA
from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy.orm import Session

from cli.crypto import rsa_verify
from . import crud, models, schemas
from .database import Base, SessionLocal, engine

Base.metadata.create_all(bind=engine)

app = FastAPI()

AUTHENTICATION_KEY = os.environ["AUTHENTICATION_KEY"]


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
    if data.authentication_key != AUTHENTICATION_KEY:
        raise HTTPException(status_code=403, detail="Permission denied.")

    try:
        ciphertext = bytes.fromhex(data.ciphertext)
        signature = bytes.fromhex(data.signature)
        rsa_public_key = RSA.import_key(data.sender_rsa_public_key)
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid sender RSA public key")

    if not rsa_verify(rsa_public_key, ciphertext, signature):
        raise HTTPException(status_code=400, detail="Invalid RSA signature")

    if (
        crud.get_share(
            db=db,
            sender_rsa_public_key=data.sender_rsa_public_key,
            recipient_rsa_public_key=data.recipient_rsa_public_key,
        )
        is not None
    ):
        raise HTTPException(
            status_code=400, detail="The data for the participant was already submitted"
        )

    return crud.create_share(
        db=db,
        sender_rsa_public_key=data.sender_rsa_public_key,
        recipient_rsa_public_key=data.recipient_rsa_public_key,
        enc_session_key=data.enc_session_key,
        ciphertext=data.ciphertext,
        tag=data.tag,
        nonce=data.nonce,
        signature=data.signature,
    )


@app.get("/health/", response_model=schemas.Health)
def health():
    return {"status": "OK"}


@app.post("/shares/", response_model=List[schemas.Share])
def get_shares(
    data: schemas.SharesFetch, db: Session = Depends(get_db)
) -> List[Tuple[int, str, str, str, str, str, str]]:
    if data.authentication_key != AUTHENTICATION_KEY:
        raise HTTPException(status_code=403, detail="Permission denied.")

    shares = crud.get_shares(db=db, recipient_rsa_public_key=data.rsa_public_key)
    return shares
