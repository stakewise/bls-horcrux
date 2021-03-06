import json
import os

import click
from py_ecc.bls.ciphersuites import G2ProofOfPossession as bls_pop

from cli.crypto import HorcruxPbkdf2Keystore


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
    horcrux_file = horcrux_file.strip()
    if not os.path.exists(horcrux_file):
        raise click.BadParameter("Horcrux file does not exist.")

    # read keystore from file
    with open(horcrux_file, "r") as key_file:
        keystore = HorcruxPbkdf2Keystore.create_from_json(json.load(key_file))

    signing_data = click.prompt(
        text="Enter hexadecimal encoded data to sign", type=click.STRING
    ).strip()
    if signing_data.startswith("0x"):
        signing_data = signing_data[2:]

    # decrypt and sign data
    private_key = int.from_bytes(keystore.decrypt(horcrux_password), "big")
    signature = bls_pop.Sign(private_key, bytes.fromhex(signing_data))

    click.echo(f"Signature: {click.style(f'0x{signature.hex()}', fg='green')}")
    click.echo(f"Horcrux index: {click.style(f'{keystore.index}', fg='green')}")
    click.echo(
        f"""Next steps:
1) Retrieve signatures of the same signing data from other horcruxes.
2) Run {click.style('./horcrux.sh reconstruct-signature', fg='blue')} to reconstruct the final signature.
   {click.style(f'NB! At least {keystore.threshold} signatures are required to reconstruct.', fg='yellow')}
"""
    )
