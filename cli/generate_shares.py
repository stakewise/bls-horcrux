import json
import os
from base64 import b64encode
from typing import List, Any, Dict, Tuple

import click
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from eth2deposit.cli.generate_keys import get_password

from cli.common import (
    create_password,
    DATA_DIR,
    get_read_file_path,
    get_write_file_path,
)
from cli.crypto import (
    get_bls_secret_shares,
    rsa_encrypt,
    rsa_sign,
    HorcruxPbkdf2Keystore,
)

INVALID_THRESHOLD = "Threshold must be >= 2."
INVALID_THRESHOLD_TOTAL = "Threshold cannot be larger than the total number horcruxes."


def generate_dispatcher_input(
    my_bls_public_key: str,
    my_bls_public_key_shares: List[str],
    my_bls_private_key_shares: List[int],
    my_rsa_key: RsaKey,
    all_rsa_public_keys: List[str],
) -> Tuple[List[Dict[str, Any]], int]:
    """
    Generate dispatcher input data.
    """
    input_data = []
    my_rsa_public_key_ssh = my_rsa_key.publickey().export_key("OpenSSH").decode("ascii")
    my_index = -1
    for i in range(len(all_rsa_public_keys)):
        recipient_rsa_public_key = RSA.import_key(all_rsa_public_keys[i])
        recipient_bls_private_key_share = my_bls_private_key_shares[i]

        if recipient_rsa_public_key == my_rsa_key.publickey():
            my_index = i
            continue

        encrypted_data = {
            "public_key": my_bls_public_key,
            "public_key_shares": my_bls_public_key_shares,
            "private_key_share": str(recipient_bls_private_key_share),
        }
        enc_session_key, nonce, tag, ciphertext = rsa_encrypt(
            recipient_public_key=recipient_rsa_public_key,
            data=json.dumps(encrypted_data),
        )
        signature = rsa_sign(my_rsa_key, ciphertext)

        input_data.append(
            {
                "sender_rsa_public_key": my_rsa_public_key_ssh,
                "recipient_rsa_public_key": recipient_rsa_public_key.export_key(
                    "OpenSSH"
                ).decode("ascii"),
                "enc_session_key": enc_session_key.hex(),
                "ciphertext": ciphertext.hex(),
                "nonce": nonce.hex(),
                "tag": tag.hex(),
                "signature": signature.hex(),
            }
        )

    return input_data, my_index


@click.command()
@click.option(
    "--total",
    prompt="Enter the total amount of BLS horcruxes",
    help="The total amount of horcruxes (must be bigger or equal to the threshold)",
    required=True,
    type=click.INT,
)
@click.option(
    "--threshold",
    prompt=(
        "Enter the minimum number of horcruxes required for recovering the signature"
    ),
    help="The minimum number of horcruxes required for recovering the signature",
    required=True,
    type=click.INT,
)
def generate_shares(total: int, threshold: int) -> None:
    """
    Generates shares exchanged with other horcruxes.
    """
    if threshold < 2:
        raise click.BadParameter(message=INVALID_THRESHOLD)
    if threshold > total:
        raise click.BadParameter(message=INVALID_THRESHOLD_TOTAL)

    # fetch all the participants RSA public keys
    all_rsa_public_keys_path = get_read_file_path(
        "Enter path to the file with all the RSA public keys",
        os.path.join(DATA_DIR, "all_rsa_public_keys.txt"),
    )
    with open(all_rsa_public_keys_path, "r") as f:
        all_rsa_public_keys = f.readlines()

    if len(all_rsa_public_keys) != total:
        raise click.BadParameter(
            message=f"Invalid number of RSA public keys received: expected={total},"
            f" actual={len(all_rsa_public_keys)}"
        )

    # fetch my RSA key
    my_rsa_key_path = get_read_file_path(
        "Enter path to the file where the RSA key is stored",
        os.path.join(DATA_DIR, "rsa_key.pem"),
    )

    rsa_password = get_password(text="Enter your RSA key password")
    with open(my_rsa_key_path, "r") as f:
        my_rsa_key = RSA.import_key(f.read(), passphrase=rsa_password)

    # create BLS key shares
    click.echo(
        f"Generating interim BLS keypair with Shamir's secret sharing:"
        f" total shares={total}, threshold={threshold}"
    )
    (
        my_bls_public_key,
        my_bls_public_key_shares,
        my_bls_private_key_shares,
    ) = get_bls_secret_shares(total=total, threshold=threshold)

    # generate dispatcher input data
    dispatcher_input, my_index = generate_dispatcher_input(
        my_bls_public_key=my_bls_public_key.hex(),
        my_bls_public_key_shares=[
            pub_key.hex() for pub_key in my_bls_public_key_shares
        ],
        my_bls_private_key_shares=my_bls_private_key_shares,
        my_rsa_key=my_rsa_key,
        all_rsa_public_keys=all_rsa_public_keys,
    )

    # save dispatcher input data
    dispatcher_input_path = get_write_file_path(
        "Enter path to the file where the dispatcher input should be saved",
        os.path.join(DATA_DIR, "dispatcher_input.json"),
    )

    if dispatcher_input_path.startswith(DATA_DIR) and not os.path.exists(DATA_DIR):
        os.mkdir(DATA_DIR)

    with open(dispatcher_input_path, "w") as dispatcher_file:
        json.dump(dispatcher_input, dispatcher_file)

    click.echo(
        "Saved dispatcher input to "
        f"{click.style(dispatcher_input_path, fg='green')}."
    )

    # save interim BLS key
    interim_bls_key_path = get_write_file_path(
        "Enter path to the file where the interim BLS key should be saved",
        os.path.join(DATA_DIR, "interim_bls_key.json"),
    )

    password = create_password("Enter the password that secures your interim BLS key")

    keystore = HorcruxPbkdf2Keystore.create_from_private_key(
        secret=b64encode(
            str.encode(
                json.dumps(
                    {
                        "private_key_shares": my_bls_private_key_shares,
                        "public_key_shares": [
                            share.hex() for share in my_bls_public_key_shares
                        ],
                        "public_key": my_bls_public_key.hex(),
                    }
                )
            )
        ),
        index=my_index,
        threshold=threshold,
        password=password,
    )
    with open(interim_bls_key_path, "w") as interim_file:
        interim_file.write(keystore.as_json())

    click.echo(
        "Saved interim BLS key to " f"{click.style(interim_bls_key_path, fg='green')}."
    )
