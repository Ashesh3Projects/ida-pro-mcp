"""Compatibility entry for the explicit two-instance live acceptance helper."""
import asyncio
from pathlib import Path
import shutil
import sys
from multi_instance_acceptance import main

if __name__ == "__main__":
    fixture = Path(sys.argv[1]).resolve()
    peer = fixture.parent / "peer" / fixture.name
    peer.parent.mkdir(exist_ok=True)
    shutil.copy2(fixture, peer)
    sys.argv = [sys.argv[0], "--mode", "headless", "--fixture-a", str(fixture), "--fixture-b", str(peer)]
    asyncio.run(main())
