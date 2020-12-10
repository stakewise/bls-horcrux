import json
import os
import time
from typing import Dict, List

import click
import requests

DATA_DIR = os.environ.get('DATA_DIR', os.path.join(os.getcwd(), 'data'))


def submit_dispatcher_data(dispatcher_endpoint: str, dispatcher_data: List[Dict]):
    """Submits data to the dispatcher server."""
    for data in dispatcher_data:
        response = requests.post(dispatcher_endpoint, json=data)
        if response.status_code != 200:
            print(f'Failed to submit dispatcher data: response status code={response.status_code}')
            print(f'Response data: {response.json()}')
            exit(1)
    print('Successfully submitted dispatcher data')


def poll_dispatcher(sender_rsa_public_key_hash: str, output_file: str, endpoint: str, total: int):
    """Polls data submitted by other horcruxes."""
    response = requests.get(os.path.join(endpoint, sender_rsa_public_key_hash, ''))
    if response.status_code != 200:
        raise ValueError(f'Failed to retrieve dispatcher output data: status code={response.status_code}')

    output_data = response.json()
    while len(output_data) != total - 1:
        time.sleep(5)
        response = requests.get(os.path.join(endpoint, sender_rsa_public_key_hash, ''))
        if response.status_code != 200:
            raise ValueError(f'Failed to retrieve dispatcher output data: status code={response.status_code}')
        output_data = response.json()

    with open(output_file, 'w') as dispatcher_file:
        json.dump(output_data, dispatcher_file)
    print(f'Saved dispatcher output data to {output_file}.')


@click.command()
@click.option(
    '--total',
    prompt='Enter the total amount of BLS horcruxes',
    help='The total amount of horcruxes',
    required=True,
    type=click.INT,
)
@click.option(
    '--dispatcher-endpoint',
    prompt='Enter the dispatcher endpoint',
    help='The URL of the dispatcher server',
    required=True,
    type=click.STRING
)
@click.option(
    '--submit-dispatcher-input',
    help='Defines whether dispatcher input should be submitted',
    show_default=True,
    default=True,
    type=click.BOOL
)
@click.option(
    '--dispatcher-input-file',
    default=os.path.join(DATA_DIR, 'dispatcher_input.json'),
    show_default=True,
    help='The file name where the dispatcher input is located',
    type=click.Path(exists=True, file_okay=True, dir_okay=False, writable=False, readable=True)
)
@click.option(
    '--dispatcher-output-file',
    default=os.path.join(DATA_DIR, 'dispatcher_output.json'),
    show_default=True,
    help='The file name where the dispatcher output should be saved',
    type=click.Path(exists=False, file_okay=True, dir_okay=False, writable=True, readable=False)
)
def handle_dispatcher(
        total: int,
        dispatcher_endpoint: str,
        dispatcher_input_file: str,
        dispatcher_output_file: str,
        submit_dispatcher_input: bool) -> None:
    """
    Sends data to the dispatcher and retrieves the output designated to the horcrux.
    Should only be used when creating horcrux in offline mode.
    """
    if not os.path.exists(dispatcher_input_file):
        raise click.BadParameter(f'Dispatcher input file does not exist at {dispatcher_input_file}')
    if os.path.exists(dispatcher_output_file):
        raise click.BadParameter(f'Dispatcher output file already exists at {dispatcher_output_file}')

    with open(dispatcher_input_file, 'r') as dispatcher_file:
        input_data = json.load(dispatcher_file)

    if submit_dispatcher_input:
        submit_dispatcher_data(dispatcher_endpoint, input_data)

    poll_dispatcher(
        sender_rsa_public_key_hash=input_data[0]['sender_rsa_public_key_hash'],
        output_file=dispatcher_output_file,
        endpoint=dispatcher_endpoint,
        total=total
    )
