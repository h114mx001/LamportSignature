from os import urandom
import pytest 
from LamportSignature.PRSignatureTree import LamportDeterministicSignatureTree

@pytest.mark.task4
def test_one_time_deterministic_tree():
    key = urandom(16)
    counter_key = urandom(16)
    L = 3
    signature_tree = LamportDeterministicSignatureTree(L, key, counter_key)
    message = urandom(32)
    signature = signature_tree.sign(message)
    result = signature_tree.verify(message, signature)
    assert result == True

@pytest.mark.task4
def test_five_time_deterministic_tree():
    key = urandom(16)
    L = 3
    counter_key = urandom(16)
    signature_tree = LamportDeterministicSignatureTree(L, key, counter_key=counter_key)
    for i in range(0, 5):
        message = urandom(32)
        signature = signature_tree.sign(message)
        result = signature_tree.verify(message, signature)
        assert result == True

@pytest.mark.task4
def test_forty_time_deterministic_tree():
    key = urandom(16)
    L = 6
    counter_key = urandom(16)
    signature_tree = LamportDeterministicSignatureTree(L, key, counter_key)
    for i in range(0, 40):
        message = urandom(32)
        signature = signature_tree.sign(message)

        result = signature_tree.verify(message, signature)
        assert result == True
