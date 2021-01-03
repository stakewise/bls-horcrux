from typing import Iterator, List, Tuple

from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy.orm import Session

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
    share: schemas.ShareCreate, db: Session = Depends(get_db)
) -> models.Share:
    if (
        crud.get_share(
            db=db,
            sender_rsa_public_key_hash=share.sender_rsa_public_key_hash,
            recipient_rsa_public_key_hash=share.recipient_rsa_public_key_hash,
        )
        is not None
    ):
        raise HTTPException(
            status_code=400, detail="The data for the participant was already submitted"
        )
    return crud.create_share(db=db, share=share)


@app.get("/{public_key_hash}/", response_model=List[schemas.Share])
def get_shares(
    public_key_hash: str, db: Session = Depends(get_db)
) -> List[Tuple[int, str, str, str, str, str, str]]:
    shared = crud.get_shares(db=db, public_key_hash=public_key_hash)
    return shared
