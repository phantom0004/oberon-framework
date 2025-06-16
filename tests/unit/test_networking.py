import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "src")))
from components import networking


def test_secure_channel_encrypt_decrypt_roundtrip():
    key = b"0" * 32
    channel = networking.SecureChannel(key)
    plaintext = "hello"
    encrypted = channel.encrypt(plaintext)
    assert plaintext.encode() == channel.decrypt(encrypted)


