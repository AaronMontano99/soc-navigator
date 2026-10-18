"""python -m app.replay [--no-fetch]: download the recordings if needed, replay them, write docs/replay-report.md."""

import os
import sys

from app.replay.evaluate import ROOT, evaluate, fetch, manifest, report

if __name__ == "__main__":
    if "--no-fetch" not in sys.argv:
        fetch(manifest())
    texts = [report(evaluate(split=split)) for split in ("dev", "holdout")]
    path = os.path.join(ROOT, "docs", "replay-report.md")
    with open(path, "w") as f:
        f.write("\n\n".join(texts))
    print("\n\n".join(texts))
    print(f"written to {path}")
