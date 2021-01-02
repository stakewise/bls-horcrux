import sys

import click

from cli.create import create
from cli.handle_dispatcher import handle_dispatcher
from cli.reconstruct_signature import reconstruct_signature
from cli.sign import sign
from cli.verify_signature import verify_signature


def check_python_version() -> None:
    """
    Checks that the python version running is sufficient and exits if not.
    """
    if sys.version_info < (3, 8):
        click.pause(
            "Your python version is insufficient, please install version 3.8 or greater."
        )
        sys.exit()


@click.group()
def cli() -> None:
    pass


cli.add_command(create)
cli.add_command(handle_dispatcher)
cli.add_command(sign)
cli.add_command(reconstruct_signature)
cli.add_command(verify_signature)

if __name__ == "__main__":
    check_python_version()
    cli()
