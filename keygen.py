from os import urandom 
from base64 import b64encode

def keygen():
    return b64encode(urandom(32)).decode()

with open("setup.cfg", "w") as f:
    f.write("[keys]\n")
    f.write(f"secret_seed=\"{keygen()}\"\n")