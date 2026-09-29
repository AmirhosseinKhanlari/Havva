"""Single shared-token auth via a signed cookie."""
from __future__ import annotations

import logging

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from itsdangerous import BadSignature, URLSafeSerializer

from ..config import _env
from .app import templates

log = logging.getLogger("web.auth")
COOKIE_NAME = "satella_session"


def _serializer() -> URLSafeSerializer:
    secret = _env("WEB_AUTH_TOKEN", "") or "insecure-dev-secret"
    return URLSafeSerializer(secret, salt="satella")


def _valid_cookie(request: Request) -> bool:
    raw = request.cookies.get(COOKIE_NAME)
    if not raw:
        return False
    try:
        return _serializer().loads(raw) == "ok"
    except BadSignature:
        return False


def require_auth(request: Request) -> None:
    if _valid_cookie(request):
        return
    raise HTTPException(status_code=307, headers={"Location": "/login"})


def mount_auth(app: FastAPI) -> None:
    token = _env("WEB_AUTH_TOKEN", "")
    if not token:
        log.warning("WEB_AUTH_TOKEN is empty; the console is UNPROTECTED. Set it in .env.")

    @app.get("/login")
    def login_form(request: Request):
        return templates.TemplateResponse(request, "login.html", {"request": request})

    @app.post("/login")
    def login(request: Request, token_in: str = Form(alias="token", default="")):
        if token and token_in == token:
            resp = RedirectResponse("/", status_code=302)
            resp.set_cookie(COOKIE_NAME, _serializer().dumps("ok"),
                            httponly=True, samesite="lax")
            return resp
        return templates.TemplateResponse(request, "login.html", {"request": request, "error": "Invalid token"}, status_code=401)

    @app.get("/logout")
    def logout():
        resp = RedirectResponse("/login", status_code=302)
        resp.delete_cookie(COOKIE_NAME)
        return resp
