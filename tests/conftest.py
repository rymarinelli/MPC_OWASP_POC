import sys
from pathlib import Path

# Ensure the project root is on the import path when tests execute.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
