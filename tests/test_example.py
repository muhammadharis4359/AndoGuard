"""Test executing the public library usage example."""

from examples.library_usage import main as example_main


def test_public_library_example(capsys: object) -> None:
    example_main()
