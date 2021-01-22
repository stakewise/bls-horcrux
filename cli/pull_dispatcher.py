import json
import os
import time
from typing import Dict, List

import click
import requests
from Crypto.PublicKey import RSA
from eth2deposit.cli.generate_keys import get_password

from cli.common import DATA_DIR, get_read_file_path, get_write_file_path


def poll_dispatcher(
    rsa_public_key: str,
    endpoint: str,
    total: int,
    auth_key: str,
) -> List[Dict[str, str]]:
    """Polls data submitted by other horcruxes."""
    data = {
        "rsa_public_key": rsa_public_key,
        "authentication_key": auth_key,
    }
    url = os.path.join(endpoint, "shares", "")
    response = requests.post(url, json=data)
    if response.status_code != 200:
        raise ValueError(
            "Failed to retrieve dispatcher output data: "
            f"status code={response.status_code}"
        )

    click.echo("Waiting for other horcruxes to submit their dispatcher data...")
    output_data = response.json()
    while len(output_data) != total - 1:
        time.sleep(5)
        response = requests.post(url, json=data)
        if response.status_code != 200:
            raise ValueError(
                "Failed to retrieve dispatcher output data: "
                f"status code={response.status_code}"
            )
        output_data = response.json()

    return output_data


@click.command()
@click.option(
    "--dispatcher-endpoint",
    prompt="Enter the dispatcher endpoint",
    help="The URL of the dispatcher server",
    required=True,
    type=click.STRING,
)
@click.option(
    "--auth-key",
    prompt="Enter the dispatcher authentication key",
    help="The dispatcher authentication key",
    required=True,
    type=click.STRING,
)
@click.option(
    "--total",
    prompt="Enter the total amount of BLS horcruxes",
    help="The total amount of horcruxes",
    required=True,
    type=click.INT,
)
def pull_dispatcher(dispatcher_endpoint: str, auth_key: str, total: int) -> None:
    """Pulls data from the dispatcher or waits once all the horcruxes submit their input"""
    # get RSA public key
    rsa_public_key = click.prompt(
        text="Enter your RSA public key", type=click.STRING
    ).strip()

    # pull dispatcher
    dispatcher_output_data = poll_dispatcher(
        rsa_public_key=rsa_public_key,
        endpoint=dispatcher_endpoint,
        total=total,
        auth_key=auth_key,
    )

    # save dispatcher output
    dispatcher_output_path = get_write_file_path(
        "Enter path to the file where the dispatcher output should be saved",
        os.path.join(DATA_DIR, "dispatcher_output.json"),
    )

    if dispatcher_output_path.startswith(DATA_DIR) and not os.path.exists(DATA_DIR):
        os.mkdir(DATA_DIR)

    with open(dispatcher_output_path, "w") as dispatcher_file:
        json.dump(dispatcher_output_data, dispatcher_file)

    click.echo(
        "Saved dispatcher output data to "
        f"{click.style(f'{dispatcher_output_path}', fg='green')}"
    )
    click.echo(
        f"""Next steps:
1) Move {click.style(dispatcher_output_path, fg='blue')} to your offline PC.
2) Run {click.style('./horcrux.sh create-horcrux', fg='blue')} on your offline PC.
"""
    )
