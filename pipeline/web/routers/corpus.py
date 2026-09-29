"""Corpus browser: searchable, multi-field filterable, paginated app table."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import Response

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


@router.post("/corpus/add")
def corpus_add(request: Request, identifier: str = Form(...),
               country: str = Form("us"), _: None = Depends(require_auth)):
    """Add an app not in the corpus by App Store id or bundle id, then open it."""
    from ... import crawl
    app_id = crawl.add_app(get_db(), identifier, country or "us")
    if not app_id:
        return templates.TemplateResponse(
            request, "_add_result.html",
            {"request": request, "error": f"No App Store match for '{identifier}' in {country.upper()}"})
    # HTMX: navigate the browser to the new app's detail page.
    return Response(status_code=204, headers={"HX-Redirect": f"/app/{app_id}"})


@router.get("/corpus/search")
def corpus_search(request: Request, term: str = "", identifier: str = "",
                  country: str = "us", _: None = Depends(require_auth)):
    """Search the App Store by name; results can be added to the corpus."""
    from ... import crawl
    term = (term or identifier or "").strip()
    results = crawl.search_appstore(term, country or "us") if term else []
    return templates.TemplateResponse(request, "_add_result.html",
                                      {"request": request, "results": results,
                                       "country": country, "term": term})
