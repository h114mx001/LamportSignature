
from LamportSignature.Lamport import LamportSignature, Lamport_ChaCha20_SHA256_keygen   
from LamportSignature.AES_PRF import AES_PRF
from LamportSignature.Counter import IncreasementCounter, Counter, DeterministicCounter

import json

class LamportSignatureTree_Signature:
    '''
    Define the signature layout for the Lamport signature tree
    '''
    def __init__(self, counter, authentication_path_signature: list[LamportSignature], signature: LamportSignature):
        '''
        Initialize the signature with the authentication path, message, and signature
        + authentication_path: The authentication path for the signature
        + message: The message that is signed
        + signature: The signature
        '''
        self.counter = counter
        self.authentication_path_signature = authentication_path_signature
        self.signature = signature

    def serialize(self) -> str: 
        '''
        Serialize the signature
        '''
        return json.dumps({
            "counter": self.counter,
            "authentication_path_signature": [signature.serialize() for signature in self.authentication_path_signature],
            "signature": self.signature.serialize()
        })

    @staticmethod
    def deserialize(serialized_signature: str):
        '''
        Deserialize the signature
        '''
        signature_dict = json.loads(serialized_signature)
        counter = signature_dict["counter"]
        authentication_path_signature = [LamportSignature.deserialize(signature) for signature in signature_dict["authentication_path_signature"]]
        signature = LamportSignature.deserialize(signature_dict["signature"])
        return LamportSignatureTree_Signature(counter, authentication_path_signature, signature)

# Task #3
class LamportPRSignatureTree_Node:
    '''
    Design of the signature tree, in order to verify as a binary tree.
    ''' 
    def __init__(self, id: int, prf: AES_PRF):
        '''
        Initialize the node with an id and a PRF, in security level L
        '''
        # Lamport's specific attributes
        self.id = id 
        self.prf = prf 
        
        # Binary tree's specific attributes
        self.is_root = False 
        if self.id == 0:
            self.is_root = True
        self.left = None
        self.right = None
        self.parent = None

        # check if the node has signed something...
        self.signed = False
        # signature caching, for the authentication path
        self.signature = None
        key = self.prf.eval(self.id)
        lamport = Lamport_ChaCha20_SHA256_keygen(key)
        self.verify_key = lamport.get_verify_key_pairs()

    def is_leaf_node(self):
        '''
        Check if this node is a leaf node
        '''
        return (self.left == None and self.right == None)
    
    def sign(self, message: bytes):
        '''
        Sign a message for the node
        + message: The message to sign
        '''
        # if the node is not the leaf node, the signature is actually for authentication path. we can cache it to avoid recomputation.
        # else, if the leaf node reuse the sign key, raise error
        if self.signed:
            if (not self.is_leaf_node()):
                return self.signature
            raise Exception("No reuse leaf's sign key for different message!")
        
        key = self.prf.eval(self.id)
        lamport = Lamport_ChaCha20_SHA256_keygen(key)
        signature = lamport.hash_and_sign(message)
        self.signed = True
        self.signature = signature
        return signature
    
    def verify(self, message: bytes, signature: LamportSignature): 
        '''
        Verify a message by the node's verify key pair
        + message: The message to verify
        + signature: The signature to verify
        '''
        return self.verify_key.hash_and_verify(message, signature)
        
    def get_children_verify_keys(self):
        '''
        Get the verify keys of the children's node
        '''
        left_node_verify_keys = self.left.verify_key.get_verify_key_pair_as_bytes()
        right_node_verify_keys = self.right.verify_key.get_verify_key_pair_as_bytes()
        return left_node_verify_keys + right_node_verify_keys

    def get_authentication_path_signature(self) -> LamportSignature:
        '''
        Return the signature of the children's node for the authentication path.
        '''
        # if the node is a leaf node, return None 
        if self.is_leaf_node():
            return None
        # Only need to have the signature, but not the whole object. we can regen them in verification step later on
        return self.sign(self.get_children_verify_keys())

    def traverse_up_to_root(self):
        '''
        Traverse up to the root node and return the authentication path 
        '''
        node = self
        authentication_path = []
        while node is not None:
            authentication_path.append(node)
            node = node.parent
        return authentication_path[:0:-1]
    
class LamportPRSignatureTree:
    '''
    Design of a SignatureTree, with prescribed security level L.
    This signature has a counter start from 0, and the leaf node has the same value with the counter.
    '''
    def __init__(self, L: int, key: bytes = None, counter: Counter=None):
        '''
        Initialize the tree with a security level L (L is the depth of the tree, do not count the root node)
        '''

        self.L = L 
        self.prf = AES_PRF(key=key)
        # counter to count which leaf node to use for signing
        
        # starting leaf has same value with the 1st counter.
        self.offset = 2**self.L - 1
        self.leaves = [None for _ in range(2**self.L)]
        # self.capacity = 2**self.L - 1
        capacity = 2**self.L - 1
        if counter is None:
            self.counter = IncreasementCounter(0, capacity)
        else:
            self.counter = counter
        self.__build_tree(L=self.L)
        
    def __str__(self):
        '''
        String representation, mostly for debug
        '''
        return f"Signature Tree with L = {self.L}, current counter = {self.counter}, capacity = {self.capacity}"
    
    def __build_tree(self, root: LamportPRSignatureTree_Node = None, L: int = None):
        '''
        Build the tree with L levels. 
        '''
        if L == 0:
            self.leaves[root.id - self.offset] = root
            return
        if root is None:
            self.root = LamportPRSignatureTree_Node(0, self.prf)
            self.__build_tree(self.root, L)
        else:
            root.left = LamportPRSignatureTree_Node(root.id * 2 + 1, self.prf)
            root.right = LamportPRSignatureTree_Node(root.id * 2 + 2, self.prf)
            root.left.parent = root
            root.right.parent = root
            self.__build_tree(root.left, L - 1)
            self.__build_tree(root.right, L - 1)
     
    def __get_node_with_id(self, id: int, starting_node: LamportPRSignatureTree_Node = None):
        '''
        Get the node with a specific id
        '''
        if starting_node is None:
            starting_node = self.root
        if starting_node.id == id:
            return starting_node
        if starting_node.is_leaf_node():
            return None
        left_node = self.__get_node_with_id(id, starting_node.left)
        if left_node is not None:
            return left_node
        right_node = self.__get_node_with_id(id, starting_node.right)
        return right_node
    
    def __get_leaf_with_id(self, id: int) -> LamportPRSignatureTree_Node: 
        '''
        Get the leaf node with a specific counter. This function differ from `self.__get_node_with_id` as it will return the leaf node, using the internal cache.
        '''
        return self.leaves[id]
    
    def __get_authentication_path_signature(self, id: int):
        '''
        Get the authentication path for a node with a specific id
        '''
        node = self.__get_leaf_with_id(id)
        authentication_path = []
        while node is not None:
            authentication_path.append(node.get_authentication_path_signature())
            node = node.parent
        return authentication_path[:0:-1]
    
    def sign(self, message: bytes) -> LamportSignatureTree_Signature:
        '''
        Sign a message on the signature tree
        '''
        state = self.counter.next(message=message)
        print("next state to be signed:", state)
        if state == -1:
            raise Exception("Signature tree is full")
        # get the current node to sign
        node = self.__get_leaf_with_id(state)
        authentication_path_signature = self.__get_authentication_path_signature(state)
        signature = node.sign(message)
        # again, we don't want to store the whole lamport object, just the signature, as everything has been generated.
        signature = LamportSignatureTree_Signature(state, authentication_path_signature, signature)
        return signature
    
    def verify(self, message: bytes, signature: LamportSignatureTree_Signature):
        '''
        Verify a signature, with the offset on the signature tree
        + offset: The offset to verify the signature
        + message: The message to verify
        + signature: The signature to verify
        '''
        offset = signature.counter
        leaf_node = self.__get_leaf_with_id(offset)
        if not leaf_node.verify(message, signature.signature):
            return False
        authentication_path_signature = signature.authentication_path_signature
        authentication_path_nodes = leaf_node.traverse_up_to_root()
        if len(authentication_path_signature) != len(authentication_path_nodes):
            return False
        for n, s in zip(authentication_path_nodes, authentication_path_signature):
            node_verify_keys = n.get_children_verify_keys()
            if not n.verify(node_verify_keys, s):
                return False
        return True

# Task #4
class LamportDeterministicSignatureTree(LamportPRSignatureTree):
    '''
    Lamport Deterministic Signature tree, that uses the deterministic counter as designed in `Counter.py`
    '''
    def __init__(self, L: int, tree_key: bytes = None, counter_key: bytes=None):
        '''
        Initialize the tree with a security level L
        '''
        assert len(tree_key) == 16
        assert len(counter_key) == 16
        counter = DeterministicCounter(counter_key, 0, 2**L - 1)
        super().__init__(L, tree_key, counter=counter)
