"""Corpus browser: searchable, filterable, paginated app table."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from ..app import get_db, templates
from ..auth import require_auth

router = APIRouter()
PAGE = 50


@router.get("/corpus")
def corpus(request: Request, q: str = "", category: str = "", pinned: str = "",
           acquired: str = "", attest: str = "", page: int = 1,
           _: None = Depends(require_auth)):
    db = get_db()
    page = max(1, page)
    rows, total = db.search_apps(q=q, category=category, pinned=pinned,
                                 acquired=acquired, attest=attest,
                                 limit=PAGE, offset=(page - 1) * PAGE)
    ctx = {
        "request": request, "rows": rows, "total": total, "page": page,
        "pages": max(1, (total + PAGE - 1) // PAGE),
        "q": q, "category": category, "pinned": pinned,
        "acquired": acquired, "attest": attest,
        "categories": db.categories(),
        "nav": "corpus",
    }
    # HTMX partial refresh vs full page.
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "_corpus_table.html", ctx)
    return templates.TemplateResponse(request, "corpus.html", ctx)
