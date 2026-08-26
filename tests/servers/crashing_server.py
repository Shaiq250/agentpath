"""Dies immediately, the way a server with a missing dependency does."""
import sys
print("ImportError: no module named nope", file=sys.stderr, flush=True)
sys.exit(1)
