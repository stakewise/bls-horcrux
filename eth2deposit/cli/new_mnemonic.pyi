import click
from .generate_keys import generate_keys as generate_keys, generate_keys_arguments_decorator as generate_keys_arguments_decorator
from eth2deposit.key_handling.key_derivation.mnemonic import get_languages as get_languages, get_mnemonic as get_mnemonic
from eth2deposit.utils.constants import WORD_LISTS_PATH as WORD_LISTS_PATH
from typing import Any

languages: Any

def new_mnemonic(ctx: click.Context, mnemonic_language: str, **kwargs: Any) -> None: ...
