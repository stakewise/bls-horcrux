import json
import os
import time
from typing import Tuple, List, Dict, Any

import click
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from eth_typing import BLSPubkey
from py_ecc.bls import G2ProofOfPossession as bls_pop

from cli.handle_dispatcher import submit_dispatcher_data, poll_dispatcher
from utils import get_bls_secret_shares, rsa_encrypt, rsa_decrypt, PRIME, create_keystore

DATA_DIR = os.environ.get('DATA_DIR', os.path.join(os.getcwd(), 'data'))


def handle_rsa_keys(
        total: int,
        my_rsa_public_key_file: str,
        all_rsa_public_keys_file: str) -> Tuple[RsaKey, RsaKey, List[str]]:
    """
    Generates RSA keypair for communication with other horcruxes
    and waits for all the other horcruxes RSA public keys.
    """
    print('Generating RSA key for communication with other horcruxes...')
    my_rsa_private_key = RSA.generate(4096)
    my_rsa_public_key = my_rsa_private_key.publickey()

    if not os.path.exists(DATA_DIR):
        os.mkdir(DATA_DIR)

    with open(my_rsa_public_key_file, 'w') as public_key_file:
        public_key_file.write(my_rsa_public_key.export_key('OpenSSH').decode('ascii'))
    print(f'Saved RSA public key to {my_rsa_public_key_file}. Please share it with other horcruxes.')

    print(f'Waiting for all the horcruxes RSA public keys at {all_rsa_public_keys_file}.')
    print(f'The keys order inside the file must be the same for all the horcruxes.')
    while not os.path.exists(all_rsa_public_keys_file):
        time.sleep(5)

    with open(all_rsa_public_keys_file, 'r') as all_keys_file:
        all_rsa_public_keys = all_keys_file.readlines()

    if len(all_rsa_public_keys) != total:
        raise ValueError(f'Invalid number of RSA public keys received: expected={total},'
                         f' actual={len(all_rsa_public_keys)}')

    return my_rsa_private_key, my_rsa_public_key, all_rsa_public_keys


def handle_dispatcher(
        input_file: str,
        output_file: str,
        my_bls_public_key: str,
        my_bls_public_key_shares: List[str],
        my_bls_private_key_shares: List[int],
        my_rsa_public_key: RsaKey,
        all_rsa_public_keys: List[str],
        offline_mode: bool,
        total: int) -> Tuple[List[Dict], int]:
    """
    Creates and submits file (if not offline usage) to the dispatcher.
    :returns data received from the dispatcher, index of the horcrux in shared secret.
    """
    input_data = []
    my_rsa_public_key_hash = SHA256.new(my_rsa_public_key.export_key('OpenSSH')).digest().hex()
    for i in range(len(all_rsa_public_keys)):
        recipient_rsa_public_key = RSA.import_key(all_rsa_public_keys[i])
        recipient_bls_private_key_share = my_bls_private_key_shares[i]

        if recipient_rsa_public_key == my_rsa_public_key:
            my_index = i
            continue

        encrypted_data = {
            'public_key': my_bls_public_key,
            'public_key_shares': my_bls_public_key_shares,
            'private_key_share': str(recipient_bls_private_key_share)
        }
        enc_session_key, nonce, tag, ciphertext = rsa_encrypt(
            recipient_public_key=recipient_rsa_public_key,
            data=json.dumps(encrypted_data)
        )

        recipient_rsa_public_key_hash = SHA256.new(recipient_rsa_public_key.export_key('OpenSSH')).digest().hex()
        input_data.append({
            'sender_rsa_public_key_hash': my_rsa_public_key_hash,
            'recipient_rsa_public_key_hash': recipient_rsa_public_key_hash,
            'enc_session_key': enc_session_key.hex(),
            'ciphertext': ciphertext.hex(),
            'nonce': nonce.hex(),
            'tag': tag.hex(),
        })

    if not offline_mode:
        endpoint = click.prompt('Enter dispatcher endpoint', type=click.STRING)
        submit_dispatcher_data(endpoint, input_data)
        poll_dispatcher(
            sender_rsa_public_key_hash=my_rsa_public_key_hash,
            output_file=output_file,
            endpoint=endpoint,
            total=total
        )
    else:
        with open(input_file, 'w') as dispatcher_file:
            json.dump(input_data, dispatcher_file)
        print(f'Saved dispatcher input to {input_file}. Please submit it to the dispatcher server.')

        print(f'Waiting for dispatcher output file to be created at {output_file}...')
        while not os.path.exists(output_file):
            time.sleep(5)

    with open(output_file, 'r') as output_file:
        output_data = json.load(output_file)

    # noinspection PyUnboundLocalVariable
    return output_data, my_index


def process_dispatcher_output(
        dispatcher_output: List[Dict],
        my_bls_public_key: BLSPubkey,
        my_bls_public_key_shares: List[BLSPubkey],
        my_bls_private_key_shares: List[int],
        my_rsa_private_key: RsaKey,
        my_index: int) -> Tuple[BLSPubkey, int]:
    """
    Processes output from the dispatcher to generate final
    horcrux BLS private key and shared BLS public key.
    """
    final_public_key_shares = [my_bls_public_key]
    horcrux_private_key_shares = [my_bls_private_key_shares[my_index]]
    horcrux_public_key_shares = [my_bls_public_key_shares[my_index]]
    for encrypted_data in dispatcher_output:
        data = json.loads(rsa_decrypt(
            private_key=my_rsa_private_key,
            enc_session_key=bytes.fromhex(encrypted_data['enc_session_key']),
            nonce=bytes.fromhex(encrypted_data['nonce']),
            tag=bytes.fromhex(encrypted_data['tag']),
            ciphertext=bytes.fromhex(encrypted_data['ciphertext']),
        ))
        recipient_bls_public_keys = [bytes.fromhex(pub_key) for pub_key in data['public_key_shares']]
        horcrux_private_key_share = int(data['private_key_share'])

        if bls_pop.SkToPk(horcrux_private_key_share) != recipient_bls_public_keys[my_index]:
            raise ValueError(f'Received invalid BLS private key share.')

        final_public_key_shares.append(bytes.fromhex(data['public_key']))
        horcrux_public_key_shares.append(recipient_bls_public_keys[my_index])
        horcrux_private_key_shares.append(horcrux_private_key_share)

    final_public_key = bls_pop._AggregatePKs(final_public_key_shares)
    print(f'Shared BLS Public Key:')
    print(f'0x{final_public_key.hex()}')

    horcrux_private_key = 0
    for private_key_share in horcrux_private_key_shares:
        horcrux_private_key += private_key_share
        horcrux_private_key %= PRIME

    if bls_pop.SkToPk(horcrux_private_key) != bls_pop._AggregatePKs(horcrux_public_key_shares):
        raise ValueError('Invalid calculated horcrux private key')

    return final_public_key, horcrux_private_key


def get_password(text: str) -> str:
    return click.prompt(text, hide_input=True, show_default=False, type=str)


def validate_password_strength(password: str) -> None:
    if len(password) < 8:
        raise ValueError(f'The password length should be at least 8. Got {len(password)}.')


def validate_password(cts: click.Context, param: Any, password: str) -> str:
    is_valid_password = False

    # The given password has passed confirmation
    try:
        validate_password_strength(password)
    except Exception as e:
        click.echo(f'Error: {e} Please retype.')
    else:
        is_valid_password = True

    while not is_valid_password:
        password = get_password(text='Type the password that secures your validator keystore(s)')
        try:
            validate_password_strength(password)
        except Exception as e:
            click.echo(f'Error: {e} Please retype.')
        else:
            # Confirm password
            password_confirmation = get_password(text='Repeat for confirmation')
            if password == password_confirmation:
                is_valid_password = True
            else:
                click.echo('Error: the two entered values do not match. Please retype again.')

    return password


@click.command()
@click.option(
    '--total',
    prompt='Enter the total amount of BLS horcruxes',
    help='The total amount of horcruxes (must be bigger or equal to the threshold)',
    required=True,
    type=click.INT,
)
@click.option(
    '--threshold',
    prompt='Enter the minimum number of horcruxes required for recovering the signature',
    help='The minimum number of horcruxes required for recovering the signature',
    required=True,
    type=click.INT,
)
@click.option(
    '--offline-mode',
    default=True,
    show_default=True,
    prompt='Enable horcrux creation offline mode'
           ' (the data to the dispatcher should be submitted separately)',
    help='Defines whether the data to the dispatcher should be submitted separately',
    type=click.BOOL
)
@click.option(
    '--my-rsa-public-key-file',
    default=os.path.join(DATA_DIR, 'my_rsa_public_key.txt'),
    show_default=True,
    help='The file name where the RSA public key will be saved',
    type=click.Path()
)
@click.option(
    '--all-rsa-public-keys-file',
    default=os.path.join(DATA_DIR, 'all_rsa_public_keys.txt'),
    show_default=True,
    help="The file name with all the horcruxes' RSA public keys",
    type=click.Path()
)
@click.option(
    '--dispatcher-input-file',
    default=os.path.join(DATA_DIR, 'dispatcher_input.json'),
    show_default=True,
    help='The file name where the data for the dispatcher server will be saved',
    type=click.Path()
)
@click.option(
    '--dispatcher-output-file',
    default=os.path.join(DATA_DIR, 'dispatcher_output.json'),
    show_default=True,
    help='The file name with the dispatcher output received from other horcrux holders',
    type=click.Path()
)
@click.option(
    '--keystore-file',
    default=os.path.join(DATA_DIR, 'keystore.json'),
    prompt='Enter the path to the file where the private key will be saved',
    show_default=True,
    help='The file name where the horcrux private key will be saved',
    type=click.Path()
)
@click.password_option(
    '--keystore-password',
    callback=validate_password,
    help=('The password that will secure your keystore. You will need to re-enter this to decrypt them when '
          'you will need to sign anything. (It is recommended not to use this argument, and wait for the CLI '
          'to ask you for your password as otherwise it will appear in your shell history.)'),
    prompt='Enter the password that secures your horcrux keystore',
)
def create(
        total: int,
        threshold: int,
        my_rsa_public_key_file: str,
        all_rsa_public_keys_file: str,
        offline_mode: bool,
        dispatcher_input_file: str,
        dispatcher_output_file: str,
        keystore_file,
        keystore_password) -> None:
    """
    Creates a new BLS horcrux using Shamir's secret sharing and BLS
    properties while communicating with other horcruxes through the dispatcher.
    Runs in offline mode by default.
    """
    if threshold < 2:
        raise click.BadParameter('Threshold must be >= 2.')
    if threshold > total:
        raise click.BadParameter('Threshold cannot be larger the number of total horcrux holders.')

    if os.path.exists(my_rsa_public_key_file):
        raise click.BadParameter('RSA public key file already exists.')
    if os.path.exists(dispatcher_input_file):
        raise click.BadParameter('Dispatcher input file already exists.')
    if os.path.exists(all_rsa_public_keys_file):
        raise click.BadParameter('All RSA public keys file already exists.')
    if os.path.exists(keystore_file):
        raise click.BadParameter('Keystore file already exists.')

    # RSA keys are used for encrypting/decrypting messages for other horcrux holders
    my_rsa_private_key, my_rsa_public_key, all_rsa_public_keys = handle_rsa_keys(
        total=total,
        my_rsa_public_key_file=my_rsa_public_key_file,
        all_rsa_public_keys_file=all_rsa_public_keys_file
    )

    print(f"Generating BLS keypair with Shamir's secret sharing: total shares={total}, threshold={threshold}")
    my_bls_public_key, my_bls_public_key_shares, my_bls_private_key_shares = get_bls_secret_shares(
        total=total,
        threshold=threshold
    )

    # Dispatcher is used to send and receive BLS private key shares from/to other horcruxes
    dispatcher_output, my_index = handle_dispatcher(
        input_file=dispatcher_input_file,
        output_file=dispatcher_output_file,
        my_bls_public_key=my_bls_public_key.hex(),
        my_bls_public_key_shares=[pub_key.hex() for pub_key in my_bls_public_key_shares],
        my_bls_private_key_shares=my_bls_private_key_shares,
        my_rsa_public_key=my_rsa_public_key,
        all_rsa_public_keys=all_rsa_public_keys,
        offline_mode=offline_mode,
        total=total
    )

    # Process output from the dispatcher to retrieve final public key and horcrux private key
    public_key, horcrux_private_key = process_dispatcher_output(
        dispatcher_output=dispatcher_output,
        my_bls_public_key=my_bls_public_key,
        my_bls_public_key_shares=my_bls_public_key_shares,
        my_bls_private_key_shares=my_bls_private_key_shares,
        my_rsa_private_key=my_rsa_private_key,
        my_index=my_index
    )

    # save horcrux private key to the keystore
    keystore = create_keystore(horcrux_private_key, public_key, my_index, threshold, keystore_password)
    with open(keystore_file, 'w') as key_file:
        key_file.write(keystore.as_json())
    print(f'Saved horcrux BLS private key to {keystore_file}')
