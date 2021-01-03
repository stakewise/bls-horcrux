import json
import os
from typing import Tuple, List, Dict

import click
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from eth2deposit.cli.generate_keys import validate_password
from eth2deposit.utils.constants import BLS_WITHDRAWAL_PREFIX
from eth2deposit.utils.crypto import SHA256
from eth_typing import BLSPubkey
from py_ecc.bls import G2ProofOfPossession as bls_pop

from cli.crypto import (
    get_bls_secret_shares,
    rsa_encrypt,
    rsa_decrypt,
    PRIME,
    create_keystore,
)
from cli.handle_dispatcher import submit_dispatcher_data, poll_dispatcher
from cli.utils import get_read_file_path, get_write_file_path

DATA_DIR = os.environ.get("DATA_DIR", os.path.join(os.getcwd(), "data"))


def handle_rsa_keys(total: int) -> Tuple[RsaKey, RsaKey, List[str]]:
    """
    Generates RSA keypair for communicating with other horcruxes
    and retrieves all the other horcruxes RSA public keys.
    """
    print("Generating RSA key for communicating with other horcruxes...")
    my_rsa_private_key = RSA.generate(4096)
    my_rsa_public_key = my_rsa_private_key.publickey()

    print(f'\n\n{my_rsa_public_key.export_key("OpenSSH").decode("ascii")}')
    print("\n\nShare the RSA public key above with all other horcruxes")

    my_rsa_public_key_file = get_read_file_path(
        "Enter path to the file with all the RSA public keys",
        os.path.join(DATA_DIR, "all_rsa_public_keys.txt"),
    )
    with open(my_rsa_public_key_file, "r") as f:
        rsa_public_keys = f.readlines()

    if len(rsa_public_keys) != total:
        raise ValueError(
            f"Invalid number of RSA public keys received: expected={total},"
            f" actual={len(rsa_public_keys)}"
        )

    return my_rsa_private_key, my_rsa_public_key, rsa_public_keys


def handle_dispatcher(
    my_bls_public_key: str,
    my_bls_public_key_shares: List[str],
    my_bls_private_key_shares: List[int],
    my_rsa_public_key: RsaKey,
    all_rsa_public_keys: List[str],
    offline_mode: bool,
    total: int,
) -> Tuple[List[Dict[str, str]], int]:
    """
    :returns dispatcher output data, index of the horcrux in shared BLS private key.
    """
    input_data = []
    my_rsa_public_key_hash = SHA256(my_rsa_public_key.export_key("OpenSSH")).hex()
    my_index = -1
    for i in range(len(all_rsa_public_keys)):
        recipient_rsa_public_key = RSA.import_key(all_rsa_public_keys[i])
        recipient_bls_private_key_share = my_bls_private_key_shares[i]

        if recipient_rsa_public_key == my_rsa_public_key:
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

        recipient_rsa_public_key_hash = SHA256(
            recipient_rsa_public_key.export_key("OpenSSH")
        ).hex()
        input_data.append(
            {
                "sender_rsa_public_key_hash": my_rsa_public_key_hash,
                "recipient_rsa_public_key_hash": recipient_rsa_public_key_hash,
                "enc_session_key": enc_session_key.hex(),
                "ciphertext": ciphertext.hex(),
                "nonce": nonce.hex(),
                "tag": tag.hex(),
            }
        )

    if my_index == -1:
        raise ValueError("Your RSA public key is missing in all RSA public keys file")

    if offline_mode:
        dispatcher_input_file = get_write_file_path(
            "Enter path to the file where the dispatcher input should be saved",
            os.path.join(DATA_DIR, "dispatcher_input.json"),
        )
        if dispatcher_input_file.startswith(DATA_DIR) and not os.path.exists(DATA_DIR):
            os.mkdir(DATA_DIR)
        with open(dispatcher_input_file, "w") as dispatcher_file:
            json.dump(input_data, dispatcher_file)
        print(
            f"Saved dispatcher input to {dispatcher_input_file}. "
            "Submit it to the dispatcher server."
        )

        dispatcher_output_file = get_read_file_path(
            "Enter path to the dispatcher output data",
            os.path.join(DATA_DIR, "dispatcher_output.json"),
        )
        with open(dispatcher_output_file, "r") as output_file:
            dispatcher_output_data = json.load(output_file)
    else:
        endpoint = click.prompt("Enter dispatcher endpoint", type=click.STRING)
        submit_dispatcher_data(endpoint, input_data)
        dispatcher_output_data = poll_dispatcher(
            sender_rsa_public_key_hash=my_rsa_public_key_hash,
            endpoint=endpoint,
            total=total,
            offline_mode=offline_mode,
        )

    return dispatcher_output_data, my_index


def process_dispatcher_output(
    dispatcher_output: List[Dict],
    my_bls_public_key: BLSPubkey,
    my_bls_public_key_shares: List[BLSPubkey],
    my_bls_private_key_shares: List[int],
    my_rsa_private_key: RsaKey,
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
        data = json.loads(
            rsa_decrypt(
                private_key=my_rsa_private_key,
                enc_session_key=bytes.fromhex(encrypted_data["enc_session_key"]),
                nonce=bytes.fromhex(encrypted_data["nonce"]),
                tag=bytes.fromhex(encrypted_data["tag"]),
                ciphertext=bytes.fromhex(encrypted_data["ciphertext"]),
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

        final_public_key_shares.append(bytes.fromhex(data["public_key"]))
        horcrux_public_key_shares.append(recipient_bls_public_keys[my_index])
        horcrux_private_key_shares.append(horcrux_private_key_share)

    final_public_key = bls_pop._AggregatePKs(final_public_key_shares)
    print(f"Shared BLS Public Key: 0x{final_public_key.hex()}")

    withdrawal_credentials = BLS_WITHDRAWAL_PREFIX
    withdrawal_credentials += SHA256(final_public_key)[1:]
    print(f"Withdrawal Credentials: 0x{withdrawal_credentials.hex()}")

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
@click.option(
    "--offline-mode",
    default=True,
    show_default=True,
    prompt="Enable horcrux creation offline mode"
    " (the data to the dispatcher should be submitted separately)",
    help="Defines whether the data to the dispatcher should be submitted separately",
    type=click.BOOL,
)
@click.password_option(
    "--horcrux-password",
    callback=validate_password,
    help="""
        The password that will secure your horcrux keystore.
        You will need to re-enter this to decrypt them when you will need to sign
        anything. (It is recommended not to use this argument, and wait for the CLI
        to ask you for your password as otherwise it will appear in your shell history.)
        """,
    prompt="Enter the password that secures your horcrux keystore",
)
def create(
    total: int, threshold: int, offline_mode: bool, horcrux_password: str
) -> None:
    """
    Creates a new BLS horcrux using Shamir's secret sharing and BLS
    properties while communicating with other horcruxes through the dispatcher.
    Runs in offline mode by default.
    """
    if threshold < 2:
        raise click.BadParameter("Threshold must be >= 2.")
    if threshold > total:
        raise click.BadParameter(
            "Threshold cannot be larger than the total number horcruxes."
        )

    # RSA keys are used for encrypting/decrypting messages for other horcrux holders
    my_rsa_private_key, my_rsa_public_key, all_rsa_public_keys = handle_rsa_keys(total)

    print(
        f"Generating intermediate BLS keypair with Shamir's secret sharing:"
        f" total shares={total}, threshold={threshold}"
    )
    (
        my_bls_public_key,
        my_bls_public_key_shares,
        my_bls_private_key_shares,
    ) = get_bls_secret_shares(total=total, threshold=threshold)

    # Dispatcher is used to send/receive BLS private key shares to/from other horcruxes
    dispatcher_output, my_index = handle_dispatcher(
        my_bls_public_key=my_bls_public_key.hex(),
        my_bls_public_key_shares=[
            pub_key.hex() for pub_key in my_bls_public_key_shares
        ],
        my_bls_private_key_shares=my_bls_private_key_shares,
        my_rsa_public_key=my_rsa_public_key,
        all_rsa_public_keys=all_rsa_public_keys,
        offline_mode=offline_mode,
        total=total,
    )

    # Process output from the dispatcher to retrieve final shared BLS public key
    # and BLS private key share
    public_key, withdrawal_credentials, horcrux_private_key = process_dispatcher_output(
        dispatcher_output=dispatcher_output,
        my_bls_public_key=my_bls_public_key,
        my_bls_public_key_shares=my_bls_public_key_shares,
        my_bls_private_key_shares=my_bls_private_key_shares,
        my_rsa_private_key=my_rsa_private_key,
        my_index=my_index,
    )

    # save horcrux private key to the keystore
    keystore = create_keystore(
        private_key=horcrux_private_key,
        shared_public_key=public_key.hex(),
        shared_withdrawal_credentials=withdrawal_credentials.hex(),
        index=my_index,
        threshold=threshold,
        password=horcrux_password,
    )

    keystore_file = get_write_file_path(
        "Enter path to the file where the horcrux should be saved",
        os.path.join(DATA_DIR, f"horcrux{my_index}.json"),
    )
    if keystore_file.startswith(DATA_DIR) and not os.path.exists(DATA_DIR):
        os.mkdir(DATA_DIR)
    with open(keystore_file, "w") as key_file:
        key_file.write(keystore.as_json())
    print(f"Saved horcrux to {keystore_file}")
    print(
        "The horcrux file must be stored in a secure place."
        " There will be no way to recover the horcrux if the file will be lost."
    )
    print("Forgetting your password will also make your horcrux irrecoverable.")
