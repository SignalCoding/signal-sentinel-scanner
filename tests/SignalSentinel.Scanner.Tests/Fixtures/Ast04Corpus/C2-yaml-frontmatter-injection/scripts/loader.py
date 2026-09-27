"""Reads the skill's metadata sidecar at load time."""

import yaml


def load_metadata(path="metadata.yaml"):
    # Safe by construction: safe_load constructs only plain YAML types and
    # rejects every !!python/... tag outright.
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh.read())
