"""Single shared-token auth via a signed cookie.

When WEB_AUTH_TOKEN is unset there is NO fallback secret: every protected route
refuses (redirects to /login, which explains that the token is not configured).
The old "insecure-dev-secret" default let anyone forge a session cookie on a
console bound to 0.0.0.0.
"""
from __future__ import annotations

import logging
import secrets

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from itsdangerous import BadSignature, URLSafeSerializer

from ..config import _env
from .app import templates

log = logging.getLogger("web.auth")
COOKIE_NAME = "havva_session"
COOKIE_MAX_AGE = 7 * 24 * 3600      # seconds (7 days)


def _token() -> str:
    return _env("WEB_AUTH_TOKEN", "")


def configured() -> bool:
    return bool(_token())


def _serializer() -> URLSafeSerializer | None:
    token = _token()
    if not token:
        return None
    return URLSafeSerializer(token, salt="havva")


def _valid_cookie(request: Request) -> bool:
    ser = _serializer()
    if ser is None:
        return False
    raw = request.cookies.get(COOKIE_NAME)
    if not raw:
        return False
    try:
        return ser.loads(raw) == "ok"
    except BadSignature:
        return False


def _token_matches(supplied: str) -> bool:
    token = _token()
    if not token or not isinstance(supplied, str):
        return False
    return secrets.compare_digest(supplied.encode("utf-8"), token.encode("utf-8"))


def require_auth(request: Request) -> None:
    if configured() and _valid_cookie(request):
        return
    raise HTTPException(status_code=307, headers={"Location": "/login"})


def mount_auth(app: FastAPI) -> None:
    if not configured():
        log.warning("WEB_AUTH_TOKEN is not set; the console refuses all requests "
                    "until it is configured in .env.")

    def _login_ctx(request: Request, error: str | None = None) -> dict:
        ctx = {"request": request, "configured": configured()}
        if not configured():
            ctx["error"] = ("WEB_AUTH_TOKEN is not configured on the server; "
                            "set it in .env and restart. Sign-in is disabled.")
        elif error:
            ctx["error"] = error
        return ctx

    @app.get("/login")
    def login_form(request: Request):
        return templates.TemplateResponse(request, "login.html", _login_ctx(request))

    @app.post("/login")
    def login(request: Request, token_in: str = Form(alias="token", default="")):
        if not configured():
            return templates.TemplateResponse(request, "login.html", _login_ctx(request),
                                              status_code=503)
        if _token_matches(token_in):
            resp = RedirectResponse("/", status_code=302)
            resp.set_cookie(COOKIE_NAME, _serializer().dumps("ok"),
                            max_age=COOKIE_MAX_AGE, httponly=True, samesite="lax")
            return resp
        return templates.TemplateResponse(request, "login.html",
                                          _login_ctx(request, "Invalid token"), status_code=401)

    @app.get("/logout")
    def logout():
        resp = RedirectResponse("/login", status_code=302)
        resp.delete_cookie(COOKIE_NAME)
        return resp
