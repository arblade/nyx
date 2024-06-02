from pathlib import Path
import yaml

from nyx.exceptions import FormatException

def parse_yaml(file_path:Path):
    return yaml.safe_load(str(file_path))

def check_keys(yaml_dict:dict):
    NON_OPTIONAL_KEYS = ["title", "id", "level", "detection", "protocols"]
    for key in NON_OPTIONAL_KEYS :
        if key not in yaml_dict:
            raise FormatException(f"Field missing : {key}")
def convert_yaml_dict(yaml_dict:dict):
