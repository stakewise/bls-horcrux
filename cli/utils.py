import os

import click


def get_read_file_path(text: str, default_path: str) -> str:
    read_file = click.prompt(
        text=text, type=click.STRING, show_default=True, default=default_path
    )
    while not os.path.exists(read_file):
        click.echo("File does not exist, please try again...")
        read_file = click.prompt(
            text=text, type=click.STRING, show_default=True, default=default_path
        )

    return read_file


def get_write_file_path(text: str, default_path: str) -> str:
    write_file = click.prompt(
        text=text, type=click.STRING, show_default=True, default=default_path
    )
    while os.path.exists(write_file):
        click.echo("File already exists, please try again...")
        write_file = click.prompt(
            text=text, type=click.STRING, show_default=True, default=default_path
        )

    return write_file
