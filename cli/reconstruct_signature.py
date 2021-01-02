import click
from py_ecc.bls import G2ProofOfPossession as bls_pop
from py_ecc.bls.g2_primitives import G2_to_signature, signature_to_G2
from py_ecc.optimized_bls12_381 import Z2, add, multiply
from py_ecc.utils import prime_field_inv

from utils import PRIME


def reconstruct(signatures):
    # https://github.com/dankrad/python-ibft/blob/master/bls_threshold.py
    r = Z2
    for i, sig in signatures.items():
        sig_point = signature_to_G2(sig)
        coef = 1
        for j in signatures:
            if j != i:
                coef = -coef * (j + 1) * prime_field_inv(i - j, PRIME) % PRIME
        r = add(r, multiply(sig_point, coef))
    return G2_to_signature(r)


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

    points = {}
    submitted = 0
    while True:
        if submitted == signatures:
            break

        signature = click.prompt(
            text=f"Enter the next hexadecimal encoded BLS signature ({submitted + 1}/{signatures})",
            type=click.STRING,
        )
        if signature.startswith("0x"):
            signature = signature[2:]

        signature = bytes.fromhex(signature)
        if not bls_pop._is_valid_signature(signature):
            print("The signature is invalid. Please try again.")
            continue

        index = click.prompt(
            text="Enter the horcrux index of the submitted signature (can be found in keystore file)",
            type=click.INT,
        )
        if index in points:
            print("The signature for such index was already submitted")
            continue

        points[index] = signature
        submitted += 1

    # reconstruct signature using Shamir's secret sharing
    reconstructed_signature = reconstruct(points)
    print("Reconstructed signature:")
    print(f"0x{reconstructed_signature.hex()}")
