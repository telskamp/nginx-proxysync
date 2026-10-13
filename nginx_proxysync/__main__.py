from __future__ import annotations

import os
from wsgiref.simple_server import make_server

from .web import create_app


def main() -> None:
    host = os.environ.get("NPM_SYNC_HOST", "0.0.0.0")
    port = int(os.environ.get("NPM_SYNC_PORT", "8080"))
    data_dir = os.environ.get("NPM_SYNC_DATA_DIR", "data")
    print(f"NPM Sync listening on {host}:{port}", flush=True)
    make_server(host, port, create_app(data_dir)).serve_forever()


if __name__ == "__main__":
    main()
