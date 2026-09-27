"""Reads the skill's metadata sidecar at load time."""

import yaml


def load_metadata(path="metadata.yaml"):
    # Legacy unsafe path: no Loader= argument, so PyYAML's default applies and
    # any !!python/... tag in the file is constructed rather than rejected.
    with open(path, encoding="utf-8") as fh:
        return yaml.load(fh.read())
