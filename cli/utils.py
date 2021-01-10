import os

import click


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
