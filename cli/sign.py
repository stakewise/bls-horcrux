import json
import os

import click
from py_ecc.bls.ciphersuites import G2ProofOfPossession as bls_pop

from cli.crypto import HorcruxPbkdf2Keystore

DATA_DIR = os.environ.get("DATA_DIR", os.path.join(os.getcwd(), "data"))


@click.command()
@click.option(
    "--horcrux-file",
    prompt="Enter the path to the horcrux keystore",
    help="The path to the horcrux keystore",
)
@click.password_option(
    "--horcrux-password",
    confirmation_prompt=False,
    help="""
        The password that secures your horcrux keystore.
        (It is recommended not to use this argument, and wait for the CLI to ask you
        for your password as otherwise it will appear in your shell history.)""",
    prompt="Enter the horcrux password used during your horcrux creation",
)
def sign(horcrux_file: str, horcrux_password: str) -> None:
    """Unlocks the keystore and signs the data."""
    if not os.path.exists(horcrux_file):
        raise click.BadParameter("Horcrux file does not exist.")

    # read keystore from file
    with open(horcrux_file, "r") as key_file:
        keystore = HorcruxPbkdf2Keystore.from_json(json.load(key_file))

    signing_data = click.prompt(
        text="Enter hexadecimal encoded data to sign", type=click.STRING
    )
    if signing_data.startswith("0x"):
        signing_data = signing_data[2:]

    # decrypt and sign data
    private_key = int.from_bytes(keystore.decrypt(horcrux_password), "big")
    signature = bls_pop.Sign(private_key, bytes.fromhex(signing_data))

    click.echo(f"Signature: {click.style(f'0x{signature.hex()}', fg='green')}")
    click.echo(f"Horcrux index: {click.style(f'{keystore.index}', fg='green')}")
