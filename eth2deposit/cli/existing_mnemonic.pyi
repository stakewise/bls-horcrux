import click
from .generate_keys import generate_keys as generate_keys, generate_keys_arguments_decorator as generate_keys_arguments_decorator
from eth2deposit.exceptions import ValidationError as ValidationError
from eth2deposit.key_handling.key_derivation.mnemonic import verify_mnemonic as verify_mnemonic
from eth2deposit.utils.constants import WORD_LISTS_PATH as WORD_LISTS_PATH
from typing import Any

def validate_mnemonic(cts: click.Context, param: Any, mnemonic: str) -> str: ...
def existing_mnemonic(ctx: click.Context, mnemonic: str, mnemonic_password: str, **kwargs: Any) -> None: ...
