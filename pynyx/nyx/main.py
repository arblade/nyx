from pathlib import Path
import yaml
import sys

# sys.path.append(str(Path(__file__).parent.parent.resolve()))

from nyx.model import NyxRule
from nyx.exceptions import FormatException


def parse_yaml(file_path: Path):
    with open(file_path) as f:
        raw = f.read()
    return yaml.safe_load(raw)


def check_keys(yaml_dict: dict):
    NON_OPTIONAL_KEYS = ["title", "id", "level", "detection", "protocol"]
    for key in NON_OPTIONAL_KEYS:
        if key not in yaml_dict.keys():
            raise FormatException(f"Field missing : {key}")


def convert_from_dict(yaml_dict: dict):
    return NyxRule.from_dict(yaml_dict)


def convert_from_yaml(raw_yaml: str):
    """convert from nyx raw yaml to suricata"""
    yaml_dict = yaml.safe_load(raw_yaml)
    check_keys(yaml_dict)
    rule = NyxRule.from_dict(yaml_dict)
    return rule.convert()


if __name__ == "__main__":

    rule_file = Path(__file__).parent.parent / "tests" / "rule.yml"
    parsed = parse_yaml(rule_file)
    print(parsed)
    check_keys(parsed)

    rule = convert_from_dict(parsed)
    print(rule.convert())
