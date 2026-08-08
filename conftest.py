import os
import sys

# make the top-level modules importable from tests/ regardless of how pytest is invoked
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
