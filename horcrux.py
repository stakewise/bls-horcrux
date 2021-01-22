import sys

import click

from cli.create_horcrux import create_horcrux
from cli.generate_shares import generate_shares
from cli.pull_dispatcher import pull_dispatcher
from cli.reconstruct_signature import reconstruct_signature
from cli.create_rsa_key import create_rsa_key
from cli.sign import sign
from cli.submit_dispatcher import submit_dispatcher
from cli.verify_signature import verify_signature


def check_python_version() -> None:
    """
    Checks that the python version running is sufficient and exits if not.
    """
    if sys.version_info < (3, 8):
        click.pause(
            "Your python version is insufficient, "
            "please install version 3.8 or greater."
        )
        sys.exit()


@click.group()
def cli() -> None:
    pass


cli.add_command(create_rsa_key)
cli.add_command(generate_shares)
cli.add_command(submit_dispatcher)
cli.add_command(pull_dispatcher)
cli.add_command(create_horcrux)
cli.add_command(sign)
cli.add_command(reconstruct_signature)
cli.add_command(verify_signature)

if __name__ == "__main__":
    check_python_version()
    cli()
