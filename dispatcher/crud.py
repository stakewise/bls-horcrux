from typing import List, Optional, Tuple
from sqlalchemy.orm import Session

from . import models


def create_share(
    db: Session,
    recipient_rsa_public_key_hash: str,
    sender_rsa_public_key_hash: str,
    enc_session_key: str,
    ciphertext: str,
    tag: str,
    nonce: str,
    signature: str,
) -> models.Share:
    db_share = models.Share(
        recipient_rsa_public_key_hash=recipient_rsa_public_key_hash,
        sender_rsa_public_key_hash=sender_rsa_public_key_hash,
        enc_session_key=enc_session_key,
        ciphertext=ciphertext,
        tag=tag,
        nonce=nonce,
        signature=signature,
    )
    db.add(db_share)
    db.commit()
    db.refresh(db_share)
    return db_share


def get_shares(
    db: Session, public_key_hash: str
) -> List[Tuple[int, str, str, str, str, str, str]]:
    return (
        db.query(models.Share)
        .filter(models.Share.recipient_rsa_public_key_hash == public_key_hash)
        .all()
    )


def get_share(
    db: Session, sender_rsa_public_key_hash: str, recipient_rsa_public_key_hash: str
) -> Optional[Tuple[int, str, str, str, str, str, str]]:
    return (
        db.query(models.Share)
        .filter(
            models.Share.sender_rsa_public_key_hash == sender_rsa_public_key_hash,
            models.Share.recipient_rsa_public_key_hash == recipient_rsa_public_key_hash,
        )
        .first()
    )
