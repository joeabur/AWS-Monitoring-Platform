import json
import sys
from collections.abc import Mapping


def emit_emf_metric(document: Mapping[str, object]) -> None:
    sys.stdout.write(json.dumps(document, separators=(",", ":")) + "\n")
    sys.stdout.flush()
