import argparse
from pathlib import Path
import yaml
import sys

sys.path.append(str(Path(__file__).parent.parent.resolve()))

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


def main():
    parser = argparse.ArgumentParser(description="Print the given file path.")
    parser.add_argument("file_path", type=str, help="The path of the rules file")
    args = parser.parse_args()
    rule_file = args.file_path
    parsed = parse_yaml(rule_file)
    check_keys(parsed)

    rule = convert_from_dict(parsed)
    print(rule.convert())


if __name__ == "__main__":
    main()
