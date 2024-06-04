from LamportSignature.Lamport import Lamport_ChaCha20_SHA256, Lamport_ChaCha20_SHA256_Signature
from LamportSignature.AES_PRF import AES_PRF
from LamportSignature.utils import cumulative_sum

from typing_extensions import Self 

class LamportSignatureTree_Signature:
    '''
    Define the signature layout for the Lamport signature tree
    '''
    def __init__(self, authentication_path: list[bytes], message: bytes, signature: bytes):
        '''
        Initialize the signature with the authentication path, message, and signature
        + authentication_path: The authentication path for the signature
        + message: The message that is signed
        + signature: The signature
        '''
        self.authentication_path = authentication_path
        self.message = message
        self.signature = signature

class LamportPRSignatureTree_Node:
    '''
    Design of the signature tree, in order to verify as a binary tree.
    ''' 
    def __init__(self, id: int, L: int, prf: AES_PRF):
        '''
        Initialize the node with an id and a PRF, in security level L
        '''
        self.id = id 
        self.L = L
        self.prf = prf 
        # check for left/right node
        self.is_left_node = self.__is_left_node()
        # check for leaf node
        self.is_leaf_node = self.__is_leaf_node()
        # check if the node has signed something...
        self.signed = False
        # signature caching, for the authentication path
        self.signature = None

    def __is_leaf_node(self):
        '''
        Check if this node is a leaf node
        '''
        return self.id >= cumulative_sum(self.L - 1)

    def __is_left_node(self):
        '''
        Check if this node is left/right. Will be used for the signature tree to know how to align the verify keys
        '''
        return self.id % 2
    
    def sign(self, message: bytes):
        '''
        Sign a message for the node
        + message: The message to sign
        '''

        # if the node is not the leaf node, the signature is actually for authentication path. we can cache it to avoid recomputation.
        if (not self.is_leaf_node) and self.signed:
            return self.signature
        
        key = self.prf.eval(self.id)
        lamport = Lamport_ChaCha20_SHA256(key)
        self.verify_key_0, self.verify_key_1 = self.lamport.get_verify_key_pair()
        signature = lamport.sign_256_bit_message(message)
        self.signed = True
        return signature
    
    def get_verify_key_pair_as_bytes(self) -> bytes: 
        '''
        Get the verify key pair as bytes
        '''
        return b"".join([self.verify_key_0, self.verify_key_1])
        
    def verify(self, message: bytes, signature: bytes): 
        '''
        Verify a message by the node's verify key pair
        + message: The message to verify
        + signature: The signature to verify
        '''
        return Lamport_ChaCha20_SHA256_Signature(message, self.verify_key_0, self.verify_key_1, signature).verify()

    def get_parent_id(self):
        '''
        Get the parent node id of the current node. If the node is root (id = 0), return 0.
        '''
        # If the node is the root, return 0
        if self.id == 0:
            return 0
        return (self.id - 1) // 2
    
    def get_child_pairs(self):
        '''
        Get the child pairs of the current node. If the node is leaf, return None
        '''
        if self.is_leaf_node:
            return None
        left_child_id = 2 * self.id + 1
        right_child_id = 2 * self.id + 2
        return left_child_id, right_child_id

class LamportPRSignatureTree:
    '''
    Design of a SignatureTree, with prescribed security level L 
    '''
    def __init__(self, L: int, key: bytes = None):
        # assert that L is a logarithm of 2      
        self.L = L 
        self.prf = AES_PRF(key=key)
        # counter to count which leaf node to use for signing
        self.counter = self.L - 1
        self.capacity = cumulative_sum(self.L)
        self.build_tree()

    def build_tree(self, L: int = None):
        '''
        Build the tree with L levels. 
        '''
        if L is None:
            L = self.L
        # the tree is represented as a list of nodes, size cumulative_sum(L)
        self.tree = [LamportPRSignatureTree_Node(id, self.L, self.prf) for id in range(cumulative_sum(L))]

    def get_authentication_path(self):
        '''
        Get the authentication path for a node with id. 
        '''
        id = self.counter
        id = (id - 1) // 2
        path = []
        while id != 0:
            path.append(id)
            id = (id - 1) // 2
        # return path
        # path = path[::-1]
        print(path)

    def sign(self, message: bytes):
        '''
        '''
        if self.counter >= self.capacity:
            raise Exception("Signature tree is full")
        