import os

import click
from Crypto.PublicKey import RSA

from cli.common import DATA_DIR, get_write_file_path, create_password


@click.command()
def create_rsa_key() -> None:
    """
    Creates a new RSA keypair for communicating with other horcruxes.
    """
    private_key_path = get_write_file_path(
        "Enter path to the file where the RSA private key should be saved",
        os.path.join(DATA_DIR, "rsa_key.pem"),
    )
    if private_key_path.startswith(DATA_DIR) and not os.path.exists(DATA_DIR):
        os.mkdir(DATA_DIR)

    click.echo("Generating RSA key for communicating with other horcruxes...")
    rsa_key = RSA.generate(4096)

    click.secho(
        f'\n\n{rsa_key.publickey().export_key("OpenSSH").decode("ascii")}\n\n',
        fg="green",
    )

    password = create_password("Enter the password that secures your RSA key")

    private_key = rsa_key.export_key(passphrase=password)
    file_out = open(private_key_path, "wb")
    file_out.write(private_key)
    file_out.close()
    click.echo(f"Saved RSA private key to {click.style(private_key_path, fg='green')}")
    click.echo(
        f"""Next steps:
1) Share the RSA public key above with all other participants.
2) Paste yours and other participants' RSA public keys to
   {click.style(os.path.join(DATA_DIR, 'all_rsa_public_keys.txt'), fg='blue')} file.
   {click.style(f'NB! The file must be equal for all the participants.', fg='yellow')}
3) Run {click.style('./horcrux.sh create-bls-key', fg='blue')} on your offline PC.
""")
