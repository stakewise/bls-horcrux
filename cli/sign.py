import json
import os

import click
from py_ecc.bls.ciphersuites import G2ProofOfPossession as bls_pop

from cli.crypto import HorcruxPbkdf2Keystore


@click.command()
@click.option(
    "--payloads-file",
    required=False,
    help="The path to the file containing signing payloads. Defaults to ./payloads.json",
    default="./payloads.json",
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
)
@click.option(
    "--output-file",
    required=False,
    help="The file to save signatures to. Defaults to ./output.json.",
    default="./output.json",
    type=click.Path(exists=False, file_okay=True, dir_okay=False),
)
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
def sign(
    payloads_file: str, output_file: str, horcrux_file: str, horcrux_password: str
) -> None:
    """Unlocks the keystore and signs the data."""
    horcrux_file = horcrux_file.strip()
    if not os.path.exists(horcrux_file):
        raise click.BadParameter("Horcrux file does not exist.")

    # read keystore from file
    with open(horcrux_file, "r") as key_file:
        keystore = HorcruxPbkdf2Keystore.create_from_json(json.load(key_file))

    click.echo(f"Loading payloads from {payloads_file}...")
    with open(payloads_file, "r") as f:
        payloads = json.load(f)

    # decrypt and sign data
    private_key = int.from_bytes(keystore.decrypt(horcrux_password), "big")

    click.echo("Signing payloads...")
    signatures = {}
    for index, payload in payloads.items():
        signature = bls_pop.Sign(private_key, bytes.fromhex(payload))
        signatures[index] = signature.hex()

    with open(output_file, "w") as f:
        json.dump(signatures, f)

    click.echo(f"Signatures saved to {click.style(output_file, fg='green')}...")
    click.echo(f"Horcrux index: {click.style(f'{keystore.index}', fg='green')}")
    click.echo(
        f"""Next steps:
1) Retrieve signatures of the same signing data from other horcruxes.
2) Run {click.style('./horcrux.sh reconstruct-signature', fg='blue')} to reconstruct the final signature.
   {click.style(f'NB! At least {keystore.threshold} signatures are required to reconstruct.', fg='yellow')}
"""
    )
