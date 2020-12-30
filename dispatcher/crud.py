from sqlalchemy.orm import Session

from . import models, schemas


def create_share(db: Session, share: schemas.ShareCreate):
    db_share = models.Share(**share.dict())
    db.add(db_share)
    db.commit()
    db.refresh(db_share)
    return db_share


def get_shares(db: Session, public_key_hash: str):
    return (
        db.query(models.Share)
        .filter(models.Share.recipient_rsa_public_key_hash == public_key_hash)
        .all()
    )


def get_share(
    db: Session, sender_rsa_public_key_hash: str, recipient_rsa_public_key_hash: str
):
    return (
        db.query(models.Share)
        .filter(
            models.Share.sender_rsa_public_key_hash == sender_rsa_public_key_hash,
            models.Share.recipient_rsa_public_key_hash == recipient_rsa_public_key_hash,
        )
        .first()
    )
