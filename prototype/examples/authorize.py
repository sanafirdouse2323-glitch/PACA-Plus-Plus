"""Run the CLI directly from a repository checkout without installing the package."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from paca_mvp.cli import main

raise SystemExit(main())
