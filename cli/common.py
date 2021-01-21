import os

import click
from eth2deposit.cli.generate_keys import get_password
from eth2deposit.exceptions import ValidationError
from eth2deposit.utils.validation import validate_password_strength

DATA_DIR = os.environ.get("DATA_DIR", os.path.join(os.getcwd(), "data"))


def create_password(text: str) -> str:
    is_valid_password = False
    password = ""
    while not is_valid_password:
        password = get_password(text=text)
        try:
            validate_password_strength(password)
        except ValidationError as e:
            click.echo(f"Error: {e} Please retype.")
        else:
            # Confirm password
            password_confirmation = get_password(text="Repeat for confirmation")
            if password == password_confirmation:
                is_valid_password = True
            else:
                click.echo(
                    "Error: the two entered values do not match. Please retype again."
                )

    return password


def get_read_file_path(text: str, default_path: str) -> str:
    read_file = click.prompt(
        text=text, type=click.STRING, show_default=True, default=default_path
    ).strip()
    while not os.path.exists(read_file):
        click.secho("File does not exist, please try again...", fg="red")
        read_file = click.prompt(
            text=text, type=click.STRING, show_default=True, default=default_path
        ).strip()

    return read_file


def get_write_file_path(text: str, default_path: str) -> str:
    write_file = click.prompt(
        text=text, type=click.STRING, show_default=True, default=default_path
    ).strip()
    while os.path.exists(write_file):
        click.secho("File already exists, please try again...", fg="red")
        write_file = click.prompt(
            text=text, type=click.STRING, show_default=True, default=default_path
        ).strip()

    return write_file
