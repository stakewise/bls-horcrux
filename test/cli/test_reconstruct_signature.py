from click.testing import CliRunner
from cli.reconstruct_signature import reconstruct_signature, INVALID_NUMBER
import pytest


@pytest.mark.parametrize("input", [0, -1])
def test_it_forbids_zero_and_negative_number_of_signatures(input):
    # given
    runner = CliRunner()

    # when
    result = runner.invoke(reconstruct_signature, ["--signatures", input])

    # then
    assert result.exit_code == 2
    assert INVALID_NUMBER in result.stdout
