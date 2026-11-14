"""The pairing token the tests use, and a test client that sends it with every request."""
from fastapi.testclient import TestClient

TOKEN = "test-token-0123456789ab"
AUTH = {"X-Guardian-Token": TOKEN}


def client(app, **kw):
    return TestClient(app, headers=AUTH, **kw)
