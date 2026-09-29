"""Corpus browser: searchable, multi-field filterable, paginated app table."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from ..app import get_db, templates
from ..auth import require_auth

router = APIRouter()
PAGE = 50

# query params that map straight through to db.search_apps
FILTERS = ("q", "category", "country", "seller", "content_rating", "tls_stack",
           "pin_library", "pinned", "attest", "devicecheck", "anti_tamper",
           "has_iap", "price", "min_ios", "min_rating", "static_done", "acquired")


@router.get("/corpus")
def corpus(request: Request, page: int = 1, _: None = Depends(require_auth)):
    db = get_db()
    qp = request.query_params
    f = {k: qp.get(k, "") for k in FILTERS}
    page = max(1, page)
    rows, total = db.search_apps(limit=PAGE, offset=(page - 1) * PAGE, **f)
    ctx = {
        "request": request, "rows": rows, "total": total, "page": page,
        "pages": max(1, (total + PAGE - 1) // PAGE),
        "f": f, "opts": db.filter_options(), "nav": "corpus",
        # querystring for pagination links (filters minus page)
        "qs": "&".join(f"{k}={v}" for k, v in f.items() if v),
    }
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "_corpus_table.html", ctx)
    return templates.TemplateResponse(request, "corpus.html", ctx)
