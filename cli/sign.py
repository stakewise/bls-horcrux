import json
import os

import click
from py_ecc.bls import G2ProofOfPossession as bls_pop

from utils import Pbkdf2Keystore

DATA_DIR = os.environ.get("DATA_DIR", os.path.join(os.getcwd(), "data"))


@click.command()
@click.option(
    "--keystore-file",
    default=os.path.join(DATA_DIR, "keystore.json"),
    prompt="Enter the path to the file where the private key will be saved",
    show_default=True,
    help="The file name where the horcrux private key will be saved",
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
)
@click.option(
    "--signing-data-file",
    default=os.path.join(DATA_DIR, "signing_data.txt"),
    show_default=True,
    prompt="Enter the path to the file where signing data is stored in hexadecimal format",
    help="The path to the file where signing data is stored in hexadecimal format",
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
)
@click.password_option(
    "--keystore-password",
    confirmation_prompt=False,
    help=(
        "The password that secures your keystore. (It is recommended not to use this argument,"
        " and wait for the CLI to ask you for your password as otherwise it will appear in your shell history.)"
    ),
    prompt="Enter the keystore password used during your horcrux encryption",
)
def sign(keystore_file: str, signing_data_file: str, keystore_password: str) -> None:
    """Unlocks the keystore and signs the data."""
    if not os.path.exists(keystore_file):
        raise click.BadParameter("Keystore file does not exist.")
    if not os.path.exists(signing_data_file):
        raise click.BadParameter("Signing data file does not exist.")

    # read keystore from file
    with open(keystore_file, "r") as key_file:
        keystore = Pbkdf2Keystore.from_json(json.load(key_file))

    # read signing data from file
    with open(signing_data_file, "r") as data_file:
        signing_data = data_file.read()

    if signing_data.startswith("0x"):
        signing_data = signing_data[2:]

    # decrypt and sign data
    private_key = int.from_bytes(keystore.decrypt(keystore_password), "big")
    signature = bls_pop.Sign(private_key, bytes.fromhex(signing_data))

    print("Signature:")
    print("0x" + signature.hex())
    print(f"Horcrux index: {keystore.index}")
