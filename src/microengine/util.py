import os


def get_test_key_and_pw():
    return os.path.join(os.path.dirname(__file__), "test_data", "keyfile"), "password"