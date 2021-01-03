import click
from eth_typing import BLSPubkey, BLSSignature
from py_ecc.bls import G2ProofOfPossession as bls_pop


@click.command()
@click.option(
    "--public-key",
    prompt=(
        "Enter the hexadecimal encoded shared BLS public key to verify "
        "(can be found in horcrux file)"
    ),
    help="The hexadecimal encoded BLS public key to verify",
    type=click.STRING,
)
@click.option(
    "--signing-data",
    prompt="Enter the hexadecimal encoded signing data",
    help="The hexadecimal encoded signing data to verify the signature for",
    type=click.STRING,
)
@click.option(
    "--signature",
    prompt="Enter the hexadecimal encoded BLS signature to verify",
    help="The signature to verify",
    type=click.STRING,
)
def verify_signature(public_key: str, signing_data: str, signature: str) -> None:
    """Verifies whether the data signature corresponds to the public key."""
    if public_key.startswith("0x"):
        public_key = public_key[2:]

    public_key = BLSPubkey(bytes.fromhex(public_key))
    if not bls_pop._is_valid_pubkey(public_key):
        raise click.BadParameter("Invalid BLS public key")

    if signature.startswith("0x"):
        signature = signature[2:]

    signature = BLSSignature(bytes.fromhex(signature))
    if not bls_pop._is_valid_signature(signature):
        raise click.BadParameter("Invalid BLS signature")

    if signing_data.startswith("0x"):
        signing_data = signing_data[2:]

    signing_data = bytes.fromhex(signing_data)

    if bls_pop.Verify(public_key, signing_data, signature):
        print("[+] The signature is valid")
    else:
        print("[-] The signature is invalid")
