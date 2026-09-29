"""Launch the Satella Console server: python3 -m pipeline.web"""
from __future__ import annotations

import uvicorn

from ..config import _env
from .app import create_app


def main() -> None:
    host = _env("WEB_HOST", "0.0.0.0")
    port = int(_env("WEB_PORT", "8770"))
    # WEB_RELOAD=1 hot-reloads on code changes (development).
    if _env("WEB_RELOAD", "") in ("1", "true", "yes"):
        uvicorn.run("pipeline.web.app:create_app", factory=True,
                    host=host, port=port, reload=True)
    else:
        uvicorn.run(create_app(), host=host, port=port)


if __name__ == "__main__":
    main()
