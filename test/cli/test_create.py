from click.testing import CliRunner
from cli.create import create, INVALID_THRESHOLD, INVALID_THRESHOLD_TOTAL
import pytest


@pytest.mark.parametrize("threshold", [1, 0, -1])
def test_it_forbids_threshold_smaller_than_two(threshold):
    # given
    runner = CliRunner()
    total = 100
    password = "any_password"

    # when
    result = runner.invoke(
        create,
        ["--total", total, "--threshold", threshold, "--horcrux-password", password],
    )

    # then
    assert result.exit_code == 2
    assert INVALID_THRESHOLD in result.stdout


def test_it_forbids_threshold_bigger_than_total():
    # given
    runner = CliRunner()
    threshold = 2
    total = 1
    password = "any_password"

    # when
    result = runner.invoke(
        create,
        ["--total", total, "--threshold", threshold, "--horcrux-password", password],
    )

    # then
    assert result.exit_code == 2
    assert INVALID_THRESHOLD_TOTAL in result.stdout
