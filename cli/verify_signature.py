import os

import click
from py_ecc.bls import G2ProofOfPossession as bls_pop

DATA_DIR = os.environ.get('DATA_DIR', os.path.join(os.getcwd(), 'data'))


@click.command()
@click.option(
    '--public-key',
    prompt='Enter the hexadecimal encoded BLS public key to verify',
    help='The hexadecimal encoded BLS public key to verify',
    type=click.STRING
)
@click.option(
    '--signature',
    prompt='Enter the hexadecimal encoded BLS signature to verify',
    help='The signature to verify',
    type=click.STRING
)
@click.option(
    '--signing-data-file',
    default=os.path.join(DATA_DIR, 'signing_data.txt'),
    show_default=True,
    prompt='Enter the path to the file where signing data is stored in hexadecimal format',
    help='The path to the file where signing data is stored in hexadecimal format',
    type=click.Path(exists=True, file_okay=True, dir_okay=False)
)
def verify_signature(public_key: str, signature: str, signing_data_file: str) -> None:
    """Verifies whether the signature for the data corresponds to submitted public key."""
    if not os.path.exists(signing_data_file):
        raise click.BadParameter('Signing data file does not exist')

    if public_key.startswith('0x'):
        public_key = public_key[2:]

    public_key = bytes.fromhex(public_key)
    if not bls_pop._is_valid_pubkey(public_key):
        raise click.BadParameter('Invalid BLS public key')

    if signature.startswith('0x'):
        signature = signature[2:]

    signature = bytes.fromhex(signature)
    if not bls_pop._is_valid_signature(signature):
        raise click.BadParameter('Invalid BLS signature')

    # read signing data from file
    with open(signing_data_file, 'r') as data_file:
        signing_data = data_file.read()

    if signing_data.startswith('0x'):
        signing_data = signing_data[2:]

    signing_data = bytes.fromhex(signing_data)

    if bls_pop.Verify(public_key, signing_data, signature):
        print('[+] The signature is valid')
    else:
        print('[-] The signature is invalid')
