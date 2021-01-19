import json
import os
import time
from typing import Any, Dict, List

import click
import requests
from eth2deposit.utils.crypto import SHA256

from cli.utils import get_read_file_path, get_write_file_path

DATA_DIR = os.environ.get("DATA_DIR", os.path.join(os.getcwd(), "data"))


def submit_dispatcher_data(
    dispatcher_endpoint: str, dispatcher_data: List[Dict[str, Any]], auth_key: str
) -> None:
    """Submits data to the dispatcher server."""
    for data in dispatcher_data:
        data["authentication_key"] = auth_key
        response = requests.post(dispatcher_endpoint, json=data)
        if response.status_code != 200:
            click.secho(
                "Failed to submit dispatcher data: "
                f"response status code={response.status_code}",
                fg="red",
            )
            click.echo(f"Response data: {response.json()}")
            exit(1)
    click.secho("Successfully submitted dispatcher data", fg="green")


def poll_dispatcher(
    sender_rsa_public_key_hash: str,
    endpoint: str,
    total: int,
    auth_key: str,
    offline_mode: bool,
) -> List[Dict[str, str]]:
    """Polls data submitted by other horcruxes."""
    data = {
        "public_key_hash": sender_rsa_public_key_hash,
        "authentication_key": auth_key,
    }
    url = os.path.join(endpoint, "shares", "")
    response = requests.post(url, data)
    if response.status_code != 200:
        raise ValueError(
            "Failed to retrieve dispatcher output data: "
            f"status code={response.status_code}"
        )

    click.echo("Waiting for other horcruxes to submit their dispatcher data...")
    output_data = response.json()
    while len(output_data) != total - 1:
        time.sleep(5)
        response = requests.post(url, data)
        if response.status_code != 200:
            raise ValueError(
                "Failed to retrieve dispatcher output data: "
                f"status code={response.status_code}"
            )
        output_data = response.json()

    if offline_mode:
        dispatcher_output_file = get_write_file_path(
            "Enter path to the file where the dispatcher output should be saved",
            os.path.join(DATA_DIR, "dispatcher_output.json"),
        )

        if dispatcher_output_file.startswith(DATA_DIR) and not os.path.exists(DATA_DIR):
            os.mkdir(DATA_DIR)

        with open(dispatcher_output_file, "w") as dispatcher_file:
            json.dump(output_data, dispatcher_file)
        click.echo(
            "Saved dispatcher output data to "
            f"{click.style(f'{dispatcher_output_file}', fg='green')}"
        )
        click.echo("Move it to your offline machine to process.")

    return output_data


@click.command()
@click.option(
    "--total",
    prompt="Enter the total amount of BLS horcruxes",
    help="The total amount of horcruxes",
    required=True,
    type=click.INT,
)
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
    "--submit-dispatcher-input",
    help="Defines whether dispatcher input should be submitted",
    show_default=True,
    default=True,
    type=click.BOOL,
)
def handle_dispatcher(
    total: int, dispatcher_endpoint: str, auth_key: str, submit_dispatcher_input: bool
) -> None:
    """
    Sends data to the dispatcher and retrieves the output designated to the horcrux.
    Should only be used when creating horcrux in offline mode.
    """
    dispatcher_endpoint = dispatcher_endpoint.strip()

    if submit_dispatcher_input:
        dispatcher_input_file = get_read_file_path(
            "Enter path to the file with the dispatcher input",
            os.path.join(DATA_DIR, "dispatcher_input.json"),
        )
        with open(dispatcher_input_file, "r") as input_file:
            input_data = json.load(input_file)

        submit_dispatcher_data(dispatcher_endpoint, input_data, auth_key)
        sender_rsa_public_key_hash = input_data[0]["sender_rsa_public_key_hash"]
    else:
        rsa_public_key = click.prompt(
            text="Enter your RSA public key", type=click.STRING
        ).strip()
        sender_rsa_public_key_hash = SHA256(rsa_public_key.encode("ascii")).hex()

    poll_dispatcher(
        sender_rsa_public_key_hash=sender_rsa_public_key_hash,
        endpoint=dispatcher_endpoint,
        total=total,
        offline_mode=True,
        auth_key=auth_key,
    )
