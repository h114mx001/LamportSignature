import configparser
from base64 import b64decode

cfg = configparser.RawConfigParser()
config_path = "setup.cfg"
cfg.read(config_path)
cfg_dict = dict(cfg.items("keys"))
secret_seed = b64decode(cfg_dict["secret_seed"])