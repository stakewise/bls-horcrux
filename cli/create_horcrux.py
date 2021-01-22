import json
import os
from base64 import b64encode, b64decode
from typing import Any, Dict, List, Tuple

import click
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from eth2deposit.cli.generate_keys import get_password
from eth2deposit.utils.constants import BLS_WITHDRAWAL_PREFIX
from eth2deposit.utils.crypto import SHA256
from eth_typing.bls import BLSPubkey
from py_ecc.bls.ciphersuites import G2ProofOfPossession as bls_pop

from cli.common import (
    create_password,
    DATA_DIR,
    get_read_file_path,
    get_write_file_path,
)
from cli.crypto import (
    PRIME,
    HorcruxPbkdf2Keystore,
    rsa_decrypt,
    rsa_verify,
)


def process_dispatcher_output(
    dispatcher_output: List[Dict[str, Any]],
    my_bls_public_key: BLSPubkey,
    my_bls_public_key_shares: List[BLSPubkey],
    my_bls_private_key_shares: List[int],
    my_rsa_key: RsaKey,
    my_index: int,
) -> Tuple[BLSPubkey, bytes, int]:
    """
    Processes output from the dispatcher to generate final
    horcrux BLS private key and shared BLS public key.
    """
    final_public_key_shares = [my_bls_public_key]
    horcrux_private_key_shares = [my_bls_private_key_shares[my_index]]
    horcrux_public_key_shares = [my_bls_public_key_shares[my_index]]
    for encrypted_data in dispatcher_output:
        # verify the RSA signature
        ciphertext = bytes.fromhex(encrypted_data["ciphertext"])
        signature = bytes.fromhex(encrypted_data["signature"])
        if not rsa_verify(
            RSA.import_key(encrypted_data["sender_rsa_public_key"]),
            ciphertext,
            signature,
        ):
            raise ValueError("Failed to verify the RSA signature.")

        data = json.loads(
            rsa_decrypt(
                private_key=my_rsa_key,
                enc_session_key=bytes.fromhex(encrypted_data["enc_session_key"]),
                nonce=bytes.fromhex(encrypted_data["nonce"]),
                tag=bytes.fromhex(encrypted_data["tag"]),
                ciphertext=ciphertext,
            )
        )
        recipient_bls_public_keys = [
            bytes.fromhex(pub_key) for pub_key in data["public_key_shares"]
        ]
        horcrux_private_key_share = int(data["private_key_share"])

        if (
            bls_pop.SkToPk(horcrux_private_key_share)
            != recipient_bls_public_keys[my_index]
        ):
            raise ValueError("Received invalid BLS private key share.")

        final_public_key_shares.append(BLSPubkey(bytes.fromhex(data["public_key"])))
        horcrux_public_key_shares.append(BLSPubkey(recipient_bls_public_keys[my_index]))
        horcrux_private_key_shares.append(horcrux_private_key_share)

    final_public_key = bls_pop._AggregatePKs(final_public_key_shares)
    click.echo(
        "Shared BLS Public Key: "
        f"{click.style(f'0x{final_public_key.hex()}', fg='green')}"
    )

    withdrawal_credentials = BLS_WITHDRAWAL_PREFIX
    withdrawal_credentials += SHA256(final_public_key)[1:]
    click.echo(
        "Withdrawal Credentials: "
        f"{click.style(f'0x{withdrawal_credentials.hex()}', fg='green')}"
    )

    horcrux_private_key = 0
    for private_key_share in horcrux_private_key_shares:
        horcrux_private_key += private_key_share
        horcrux_private_key %= PRIME

    if bls_pop.SkToPk(horcrux_private_key) != bls_pop._AggregatePKs(
        horcrux_public_key_shares
    ):
        raise ValueError("Invalid calculated horcrux private key")

    return final_public_key, withdrawal_credentials, horcrux_private_key


@click.command()
def create_horcrux() -> None:
    """Creates horcrux from intermediate files"""
    # fetch interim BLS key shares
    interim_bls_key_path = get_read_file_path(
        "Enter path to the file with interim BLS key",
        os.path.join(DATA_DIR, "interim_bls_key.json"),
    )
    with open(interim_bls_key_path, "r") as key_file:
        interim_keystore = HorcruxPbkdf2Keystore.create_from_json(json.load(key_file))

    interim_password = get_password(text="Enter your interim BLS key password")
    secret_data = json.loads(b64decode(interim_keystore.decrypt(interim_password)))

    my_bls_private_key_shares = secret_data["private_key_shares"]
    my_bls_public_key_shares = [
        BLSPubkey(bytes.fromhex(share)) for share in secret_data["public_key_shares"]
    ]
    my_bls_public_key = BLSPubkey(bytes.fromhex(secret_data["public_key"]))
    my_index = interim_keystore.index

    # fetch dispatcher output
    dispatcher_output_file = get_read_file_path(
        "Enter path to the dispatcher output data",
        os.path.join(DATA_DIR, "dispatcher_output.json"),
    )
    with open(dispatcher_output_file, "r") as output_file:
        dispatcher_output_data = json.load(output_file)

    # fetch my RSA key
    my_rsa_key_path = get_read_file_path(
        "Enter path to the file where the RSA key is stored",
        os.path.join(DATA_DIR, "rsa_key.pem"),
    )
    rsa_password = get_password(text="Enter your RSA key password")

    with open(my_rsa_key_path, "r") as f:
        my_rsa_key = RSA.import_key(f.read(), passphrase=rsa_password)

    # Process output from the dispatcher to retrieve final shared BLS public key
    # and BLS private key share
    public_key, withdrawal_credentials, horcrux_private_key = process_dispatcher_output(
        dispatcher_output=dispatcher_output_data,
        my_bls_public_key=my_bls_public_key,
        my_bls_public_key_shares=my_bls_public_key_shares,
        my_bls_private_key_shares=my_bls_private_key_shares,
        my_rsa_key=my_rsa_key,
        my_index=my_index,
    )

    # save horcrux private key to the keystore
    horcrux_password = create_password(
        "Enter the password that secures your horcrux keystore"
    )
    keystore = HorcruxPbkdf2Keystore.create_from_private_key(
        secret=horcrux_private_key.to_bytes(length=32, byteorder="big"),
        shared_public_key=public_key.hex(),
        shared_withdrawal_credentials=withdrawal_credentials.hex(),
        index=interim_keystore.index,
        threshold=interim_keystore.threshold,
        password=horcrux_password,
    )

    display_private_key = click.prompt(
        "Display the horcrux private key (e.g. to write it down)",
        type=click.BOOL,
        default="no",
    )
    if display_private_key:
        base64_horcrux_key = b64encode(
            horcrux_private_key.to_bytes(length=32, byteorder="big")
        ).decode("ascii")
        click.secho(
            f"\n\n{base64_horcrux_key}\n\n",
            fg="green",
        )

    keystore_file = get_write_file_path(
        "Enter path to the file where the horcrux should be saved",
        os.path.join(DATA_DIR, f"horcrux{my_index}.json"),
    )
    if keystore_file.startswith(DATA_DIR) and not os.path.exists(DATA_DIR):
        os.mkdir(DATA_DIR)
    with open(keystore_file, "w") as key_file:
        key_file.write(keystore.as_json())
    click.echo(f"Saved horcrux to {click.style(f'{keystore_file}', fg='green')}")
    click.secho(
        "The horcrux file must be stored in a secure place."
        " There will be no way to recover the horcrux if the file will be lost.",
        fg="blue",
    )
    click.secho(
        "Forgetting your password will also make your horcrux irrecoverable.", fg="blue"
    )
