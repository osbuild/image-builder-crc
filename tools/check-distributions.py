#!/bin/python3

import os
import sys

import yaml


def main():
    result = 0

    with open("internal/v1/api.yaml", "r", encoding="utf-8") as f:
        spec_distros = yaml.safe_load(f)["components"]["schemas"]["Distributions"]["enum"]

    for distro in os.listdir("distributions"):
        if distro not in spec_distros:
            result = 1
            print(f"Distribution {distro} is not in the v1 openapi specification, please add it under components.schemas.Distributions")

    return result


if __name__ == "__main__":
    sys.exit(main())
