from __future__ import annotations

import threading
from contextlib import asynccontextmanager
from urllib.parse import parse_qs, urlencode

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import ValidationError

from app import models, schemas
from app.api.routes import router
from app.auth_utils import utc_now
from app.config import settings
from app.db import get_db, init_db
from app.http_middleware import RequestContextMiddleware
from app.security import AuthContext, clear_session_cookie, get_optional_user, set_session_cookie
from app.services.access_control import get_analysis_run_for_user
from app.services.analysis_service import analysis_run_to_dict
from app.services.auth_service import authenticate_user
from app.services.reporting import build_dashboard_payload
from app.ui.dashboard import render_analysis_dashboard, render_home_page, render_login_page
from app.worker import run_worker_loop


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    if settings.run_embedded_worker:
        thread = threading.Thread(target=run_worker_loop, daemon=True, name="evonhi-embedded-worker")
        thread.start()
    yield


app = FastAPI(
    title="EvoNHI Enterprise Control Plane",
    version="0.3.0",
    description="Multi-tenant SaaS for non-human identity attack-path reduction with async analysis and runtime telemetry.",
    lifespan=lifespan,
)
app.add_middleware(RequestContextMiddleware)


def _safe_next_path(candidate: str | None, *, default: str = "/") -> str:
    if not candidate:
        return default
    if not candidate.startswith("/") or candidate.startswith("//"):
        return default
    return candidate


def _path_without_access_token(request: Request) -> str:
    items = [(key, value) for key, value in request.query_params.multi_items() if key != "access_token"]
    query = urlencode(items, doseq=True)
    return f"{request.url.path}?{query}" if query else request.url.path


def _login_redirect(request: Request) -> RedirectResponse:
    next_path = _safe_next_path(_path_without_access_token(request))
    return RedirectResponse(url=f"/login?{urlencode({'next': next_path})}", status_code=303)


def _upgrade_query_session(request: Request, current_user: AuthContext | None) -> RedirectResponse | None:
    raw_token = request.query_params.get("access_token")
    if not raw_token or not current_user:
        return None
    target = _path_without_access_token(request)
    response = RedirectResponse(url=target, status_code=303)
    set_session_cookie(response, raw_token)
    return response


@app.get("/health")
def healthcheck():
    return {
        "status": "ok",
        "service": "evonhi-enterprise",
        "database": "sqlite" if settings.is_sqlite else "postgresql",
        "embedded_worker": settings.run_embedded_worker,
    }


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, current_user: AuthContext | None = Depends(get_optional_user)):
    next_path = _safe_next_path(request.query_params.get("next"))
    if current_user:
        return RedirectResponse(url=next_path, status_code=303)
    return HTMLResponse(render_login_page(next_path=next_path))


@app.post("/login")
async def login_submit(request: Request, db=Depends(get_db)):
    form_data = parse_qs((await request.body()).decode("utf-8"))
    next_path = _safe_next_path(form_data.get("next", ["/"])[0])
    email = form_data.get("email", [""])[0]
    password = form_data.get("password", [""])[0]
    try:
        payload = schemas.LoginRequest(email=email, password=password)
        result = authenticate_user(
            db,
            payload,
            request_meta={
                "request_id": getattr(request.state, "request_id", None),
                "ip_address": request.client.host if request.client else None,
            },
        )
    except (ValidationError, ValueError):
        return HTMLResponse(
            render_login_page(
                next_path=next_path,
                error_message="We could not sign you in with those credentials.",
                email_value=email,
            ),
            status_code=401,
        )

    response = RedirectResponse(url=next_path, status_code=303)
    set_session_cookie(response, result["access_token"])
    return response


@app.post("/logout")
def logout(
    db=Depends(get_db),
    current_user: AuthContext | None = Depends(get_optional_user),
):
    if current_user:
        current_user.token.revoked_at = utc_now()
        db.add(current_user.token)
        db.commit()
    response = RedirectResponse(url="/login", status_code=303)
    clear_session_cookie(response)
    return response


@app.get("/", response_class=HTMLResponse)
def home(
    request: Request,
    current_user: AuthContext | None = Depends(get_optional_user),
    db=Depends(get_db),
):
    upgraded = _upgrade_query_session(request, current_user)
    if upgraded is not None:
        return upgraded
    if current_user is None:
        return _login_redirect(request)
    if current_user.user.is_platform_admin:
        runs = db.query(models.AnalysisRun).order_by(models.AnalysisRun.created_at.desc()).limit(8).all()
    else:
        tenant_ids = [membership.tenant_id for membership in current_user.memberships if membership.status == "active"]
        runs = (
            db.query(models.AnalysisRun)
            .filter(models.AnalysisRun.tenant_id.in_(tenant_ids))
            .order_by(models.AnalysisRun.created_at.desc())
            .limit(8)
            .all()
            if tenant_ids
            else []
        )
    cards = [build_dashboard_payload(analysis_run_to_dict(run)) for run in runs]
    return HTMLResponse(render_home_page(cards, auth_enabled=True, user_label=current_user.user.email))


@app.get("/dashboard/runs/{run_id}", response_class=HTMLResponse)
def analysis_dashboard(
    run_id: int,
    request: Request,
    current_user: AuthContext | None = Depends(get_optional_user),
    db=Depends(get_db),
):
    upgraded = _upgrade_query_session(request, current_user)
    if upgraded is not None:
        return upgraded
    if current_user is None:
        return _login_redirect(request)
    run = get_analysis_run_for_user(db, run_id, current_user, minimum_role="viewer")
    if not run:
        raise HTTPException(status_code=404, detail="Analysis run not found")
    payload = build_dashboard_payload(analysis_run_to_dict(run))
    return HTMLResponse(render_analysis_dashboard(payload, user_label=current_user.user.email))


app.include_router(router)
