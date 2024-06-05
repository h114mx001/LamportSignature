from os import urandom
import pytest 

from LamportSignature.PRSignatureTree import LamportPRSignatureTree, LamportSignatureTree_Signature, LamportDeterministicSignatureTree

@pytest.mark.task3
def test_one_time_signature_tree(): 
    key = urandom(16)
    L = 3 
    signature_tree = LamportPRSignatureTree(L, key)
    message = urandom(32)
    signature = signature_tree.sign(message)
    result = signature_tree.verify(message, signature)
    assert result == True

@pytest.mark.task3
def test_one_time_signature_tree_serialization():
    key = urandom(16)
    L = 3 
    signature_tree = LamportPRSignatureTree(L, key)
    message = urandom(32)
    signature = signature_tree.sign(message)
    result = signature_tree.verify(message, signature)
    assert result == True
    serialized = signature.serialize()
    new_signature = LamportSignatureTree_Signature.deserialize(serialized)
    result = signature_tree.verify(message, new_signature)
    assert result == True

@pytest.mark.task3
def test_five_time_signature_tree_serialization():
    key = urandom(16)
    L = 3 
    signature_tree = LamportPRSignatureTree(L, key)
    for _ in range(0, 5):
        message = urandom(32)
        signature = signature_tree.sign(message)
        result = signature_tree.verify(message, signature)
        assert result == True
        serialized = signature.serialize()
        new_signature = LamportSignatureTree_Signature.deserialize(serialized)
        result = signature_tree.verify(message, new_signature)
        assert result == True

@pytest.mark.task3
def test_forty_time_signature_tree_serialization():
    key = urandom(16)
    L = 6
    signature_tree = LamportPRSignatureTree(L, key)
    for _ in range(0, 40):
        message = urandom(32)
        signature = signature_tree.sign(message)
        result = signature_tree.verify(message, signature)
        assert result == True
        serialized = signature.serialize()
        new_signature = LamportSignatureTree_Signature.deserialize(serialized)
        result = signature_tree.verify(message, new_signature)
        assert result == True

@pytest.mark.task3
def test_overload_sign_tree():
    key = urandom(16)
    L = 1
    signature_tree = LamportPRSignatureTree(L, key)
    with pytest.raises(Exception):
        for _ in range(100):
            message = urandom(32)
            signature = signature_tree.sign(message)
            result = signature_tree.verify(message, signature)