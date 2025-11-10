from src.utils import greet


def test_greet(capsys):
    greet("Test")
    captured = capsys.readouterr()
    assert "Hello, Test!" in captured.out
