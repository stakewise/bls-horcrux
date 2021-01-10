import click
from eth2deposit.credentials import CredentialList as CredentialList
from eth2deposit.exceptions import ValidationError as ValidationError
from eth2deposit.settings import ALL_CHAINS as ALL_CHAINS, MAINNET as MAINNET, get_chain_setting as get_chain_setting
from eth2deposit.utils.ascii_art import RHINO_0 as RHINO_0
from eth2deposit.utils.constants import DEFAULT_VALIDATOR_KEYS_FOLDER_NAME as DEFAULT_VALIDATOR_KEYS_FOLDER_NAME, MAX_DEPOSIT_AMOUNT as MAX_DEPOSIT_AMOUNT
from eth2deposit.utils.validation import validate_password_strength as validate_password_strength, verify_deposit_data_json as verify_deposit_data_json
from typing import Any, Callable

def get_password(text: str) -> str: ...
def validate_password(cts: click.Context, param: Any, password: str) -> str: ...
def generate_keys_arguments_decorator(function: Callable[..., Any]) -> Callable[..., Any]: ...
def generate_keys(ctx: click.Context, validator_start_index: int, num_validators: int, folder: str, chain: str, keystore_password: str, **kwargs: Any) -> None: ...
