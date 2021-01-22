import json
import os
from typing import Any, Dict, List

import click
import requests

from cli.common import DATA_DIR, get_read_file_path


def submit_dispatcher_data(
    dispatcher_endpoint: str, dispatcher_data: List[Dict[str, Any]], auth_key: str
) -> None:
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
def submit_dispatcher(dispatcher_endpoint: str, auth_key: str) -> None:
    """Submits data to the dispatcher server."""
    dispatcher_endpoint = dispatcher_endpoint.strip()

    dispatcher_input_file = get_read_file_path(
        "Enter path to the file with the dispatcher input",
        os.path.join(DATA_DIR, "dispatcher_input.json"),
    )
    with open(dispatcher_input_file, "r") as input_file:
        input_data = json.load(input_file)

    submit_dispatcher_data(dispatcher_endpoint, input_data, auth_key)
    click.secho("Successfully submitted dispatcher data", fg="green")
