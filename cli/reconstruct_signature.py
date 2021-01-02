from typing import Dict

import click
from eth_typing import BLSSignature
from py_ecc.bls import G2ProofOfPossession as bls_pop

from cli.crypto import reconstruct_shared_bls_signature


@click.command()
@click.option(
    "--signatures",
    prompt="Enter the total number of BLS signatures to reconstruct the final signature from",
    help="The total number of signatures to reconstruct the final signature from",
    type=click.INT,
)
def reconstruct_signature(signatures: int) -> None:
    """Reconstructs BLS signatures using Shamir's secret sharing."""
    if signatures <= 0:
        raise click.BadParameter("Invalid signatures number.")

    points: Dict[int, BLSSignature] = {}
    submitted = 0
    while True:
        if submitted == signatures:
            break

        index = click.prompt(
            text="Enter the horcrux index of the submitted signature (can be found in the owner's horcrux file)",
            type=click.INT,
        )
        if index in points:
            print("The signature for such index was already submitted")
            continue

        signature = click.prompt(
            text=f"Enter the next hexadecimal encoded BLS signature ({submitted + 1}/{signatures})",
            type=click.STRING,
        )
        if signature.startswith("0x"):
            signature = signature[2:]

        signature = BLSSignature(bytes.fromhex(signature))
        if not bls_pop._is_valid_signature(signature):
            print("The signature is invalid. Please try again.")
            continue

        points[index] = signature
        submitted += 1

    # reconstruct signature using Shamir's secret sharing

    reconstructed_signature = reconstruct_shared_bls_signature(points)
    print(f"Reconstructed signature: 0x{reconstructed_signature.hex()}")
