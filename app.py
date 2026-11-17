"""PXzx Store — painel do Discord e migração de membros consentida.

Entrada Flask para Vercel: `app` no nível superior.
"""
from __future__ import annotations

from datetime import timedelta
from hashlib import sha256
from base64 import urlsafe_b64encode
import os
import secrets
from time import time
from urllib.parse import urlencode, urlsplit

from flask import Flask, abort, redirect, render_template, request, session, url_for
from pymongo import MongoClient
from pymongo.errors import PyMongoError
import requests

from migration import setup_migration

DISCORD_ORIGIN = "https://discord.com"
DISCORD_API = f"{DISCORD_ORIGIN}/api/v10"
CORE_KEYS = (
    "PUBLIC_BASE_URL", "DISCORD_CLIENT_ID", "DISCORD_CLIENT_SECRET",
    "DASHBOARD_OWNER_ID", "BOT_MONGO_URI", "BOT_MONGO_DATABASE",
    "SESSION_SECRET",
)


def is_snowflake(value: str) -> bool:
    return (isinstance(value, str) and value.isascii() and value.isdecimal()
            and 1 <= len(value) <= 20 and value[0] != "0" and int(value) < 2**64)


def create_app(env=None):
    env = os.environ if env is None else env
    v = {key: str(env.get(key, "")).strip() for key in CORE_KEYS}
    errors = [f"{key}: variável não configurada." for key, value in v.items() if not value]
    base = v["PUBLIC_BASE_URL"].rstrip("/")
    try:
        url = urlsplit(base)
        if v["PUBLIC_BASE_URL"] and (url.scheme != "https" or not url.netloc or
              url.username or url.password or url.path or url.query or url.fragment):
            errors.append("PUBLIC_BASE_URL: informe apenas o domínio HTTPS, sem / no final.")
    except ValueError:
        errors.append("PUBLIC_BASE_URL: endereço inválido.")
    for name in ("DISCORD_CLIENT_ID", "DASHBOARD_OWNER_ID"):
        if v[name] and not is_snowflake(v[name]):
            errors.append(f"{name}: informe um ID numérico do Discord.")
    bot_id = str(env.get("BOT_ID", "")).strip() or v["DISCORD_CLIENT_ID"]
    if bot_id and not is_snowflake(bot_id):
        errors.append("BOT_ID: informe o ID numérico do bot.")
    if v["SESSION_SECRET"] and len(v["SESSION_SECRET"]) < 32:
        errors.append("SESSION_SECRET: gere uma chave de pelo menos 32 caracteres.")

    app = Flask(__name__, static_folder=None)
    # Quando não configurado, uma chave temporária só permite mostrar a página de instalação.
    app.config.update(
        SECRET_KEY=v["SESSION_SECRET"] if len(v["SESSION_SECRET"]) >= 32 else secrets.token_urlsafe(48),
        SESSION_COOKIE_NAME="__Host-pxzx_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=4),
        SESSION_REFRESH_EACH_REQUEST=False,
        MAX_CONTENT_LENGTH=16_384,
    )

    db = None
    status_collection = None
    if v["BOT_MONGO_URI"] and v["BOT_MONGO_DATABASE"]:
        try:
            mongo = MongoClient(v["BOT_MONGO_URI"], connect=False, serverSelectionTimeoutMS=3500,
                                connectTimeoutMS=3500, socketTimeoutMS=3500)
            db = mongo[v["BOT_MONGO_DATABASE"]]
            if bot_id and is_snowflake(bot_id):
                status_collection = db[bot_id]
        except (PyMongoError, ValueError, TypeError):
            errors.append("BOT_MONGO_URI: não foi possível interpretar a conexão MongoDB.")
            db = None

    def owner_logged_in() -> bool:
        return session.get("owner_id") == v["DASHBOARD_OWNER_ID"] and bool(v["DASHBOARD_OWNER_ID"])

    def require_owner():
        if not owner_logged_in():
            abort(403)

    def csrf_token():
        return session.setdefault("csrf_token", secrets.token_urlsafe(32))

    def require_csrf():
        expected = session.get("csrf_token", "")
        actual = request.form.get("csrf_token", "")
        if not expected or not actual or not secrets.compare_digest(expected, actual):
            abort(400)

    @app.context_processor
    def common_vars():
        return {"is_owner": owner_logged_in(), "account": session.get("account", ""),
                "csrf_token": csrf_token(), "site_name": "PXzx Store"}

    @app.after_request
    def secure_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; script-src 'self'; "
            "style-src 'self'; font-src 'self'; base-uri 'none'; "
            "form-action 'self'; frame-ancestors 'none'"
        )
        return response

    @app.get("/health")
    def health():
        return {"status": "ok", "configured": not bool(errors)}

    @app.get("/")
    def index():
        return render_template("index.html", setup_needed=bool(errors))

    def start_oauth(purpose, scopes, campaign=""):
        # MongoDB ou migração podem estar pendentes: o dono ainda deve conseguir entrar
        # para ler o diagnóstico. Somente os requisitos do OAuth bloqueiam o login.
        oauth_names = ("PUBLIC_BASE_URL", "DISCORD_CLIENT_ID", "DISCORD_CLIENT_SECRET",
                       "DASHBOARD_OWNER_ID", "SESSION_SECRET")
        oauth_errors = any(any(item.startswith(name + ":") for name in oauth_names)
                           for item in errors)
        if oauth_errors:
            abort(503)
        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(56)
        challenge = urlsafe_b64encode(sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        session["oauth_request"] = {"state": state, "verifier": verifier, "time": int(time()),
                                    "purpose": purpose, "campaign": campaign}
        query = urlencode({
            "response_type": "code", "client_id": v["DISCORD_CLIENT_ID"],
            "redirect_uri": base + "/auth/discord/callback", "scope": scopes,
            "state": state, "code_challenge": challenge, "code_challenge_method": "S256",
        })
        return redirect(f"{DISCORD_ORIGIN}/oauth2/authorize?{query}", code=303)

    @app.get("/login")
    def login():
        # Não apaga a sessão antes de redirecionar: só substitui o OAuth pendente.
        return start_oauth("owner", "identify")

    @app.get("/auth/discord/callback")
    def oauth_callback():
        prior = session.pop("oauth_request", None)
        state = request.args.get("state", "")
        if (not prior or not isinstance(prior, dict) or not state or
            not secrets.compare_digest(prior.get("state", ""), state) or
            time() - prior.get("time", 0) > 600 or
            request.args.get("iss", DISCORD_ORIGIN) != DISCORD_ORIGIN):
            abort(400)
        if request.args.get("error") == "access_denied":
            return redirect(url_for("migration.migrate", msg="declined") if prior["purpose"] != "owner"
                            else url_for("index"), code=303)
        code = request.args.get("code", "")
        if not code:
            abort(400)
        try:
            response = requests.post(f"{DISCORD_API}/oauth2/token", data={
                "client_id": v["DISCORD_CLIENT_ID"], "client_secret": v["DISCORD_CLIENT_SECRET"],
                "grant_type": "authorization_code", "code": code,
                "redirect_uri": base + "/auth/discord/callback", "code_verifier": prior["verifier"],
            }, timeout=(4, 8), allow_redirects=False)
            response.raise_for_status()
            grant = response.json()
            access_token = grant.get("access_token")
            if not isinstance(access_token, str) or not access_token:
                raise ValueError("missing token")
            who = requests.get(f"{DISCORD_API}/users/@me",
                               headers={"Authorization": f"Bearer {access_token}"},
                               timeout=(4, 8), allow_redirects=False)
            who.raise_for_status()
            profile = who.json()
        except (requests.RequestException, ValueError, KeyError, TypeError):
            return render_template("error.html", error_title="Falha no Discord",
                                   message="Não foi possível concluir a autorização. Confira Client Secret e Redirect URL."), 502
        if not isinstance(profile, dict) or not is_snowflake(profile.get("id", "")):
            abort(502)
        if prior["purpose"] == "owner":
            if profile["id"] != v["DASHBOARD_OWNER_ID"]:
                abort(403)
            session.clear()
            session.permanent = True
            session["owner_id"] = profile["id"]
            session["account"] = profile.get("global_name") or profile.get("username") or "Proprietário"
            csrf_token()
            return redirect(url_for("panel"), code=303)
        return finish_member_oauth(prior["purpose"], prior["campaign"], grant, profile)

    @app.get("/painel")
    def panel():
        require_owner()
        names = []
        saved = request.args.get("saved") == "1"
        err = ""
        pending = None
        try:
            if status_collection is not None:
                doc = status_collection.find_one({"_id": "custom_status"}, {"names": 1, "name": 1})
                if isinstance(doc, dict):
                    values = doc.get("names")
                    if not isinstance(values, list) or not values:
                        values = [doc.get("name", "")]
                    names = [x for x in values if isinstance(x, str) and x.strip()][:5]
            if migration_ready and db is not None:
                pending = db["discord_migration_consents"].count_documents(
                    {"campaign": migration_campaign, "expires_at": {"$gt": utcnow()}})
        except PyMongoError:
            err = "O MongoDB não respondeu. Confira a conexão de rede e o banco selecionado."
        return render_template("panel.html", section="overview", names=names, pending=pending,
                               saved=saved, error=err, config_errors=errors,
                               migration_ready=migration_ready)

    @app.post("/painel/status")
    def save_status():
        require_owner()
        require_csrf()
        names = [line.strip() for line in request.form.get("names", "").splitlines() if line.strip()]
        if not 1 <= len(names) <= 5 or any(len(line) > 100 for line in names):
            return render_template("error.html", error_title="Texto inválido",
                                   message="Informe de 1 a 5 frases com até 100 caracteres cada."), 400
        if status_collection is None:
            return render_template("error.html", error_title="Banco indisponível",
                                   message="Confira BOT_MONGO_URI, BOT_MONGO_DATABASE e BOT_ID."), 503
        try:
            status_collection.update_one({"_id": "custom_status"},
                                         {"$set": {"names": names}, "$unset": {"name": ""}}, upsert=True)
        except PyMongoError:
            return render_template("error.html", error_title="Não foi possível salvar",
                                   message="O MongoDB está indisponível."), 503
        return redirect(url_for("panel", saved="1"), code=303)

    @app.post("/logout")
    def logout():
        require_owner()
        require_csrf()
        session.clear()
        return redirect(url_for("index"), code=303)

    @app.get("/privacidade")
    def privacy():
        return render_template("privacy.html")

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(503)
    def error_page(error):
        titles = {400: "Solicitação inválida", 403: "Acesso restrito",
                  404: "Página não encontrada", 503: "Serviço ainda não configurado"}
        descriptions = {
            400: "Recarregue a página e tente novamente.",
            403: "Esta área é exclusiva do proprietário configurado no painel.",
            404: "Confira o endereço e tente novamente.",
            503: "Confira as variáveis de ambiente da Vercel e publique um novo deploy.",
        }
        return render_template("error.html", error_title=titles[error.code],
                               message=descriptions[error.code]), error.code

    finish_member_oauth, migration_ready, migration_campaign, utcnow = setup_migration(
        app, env, db, v["DISCORD_CLIENT_ID"], errors, owner_logged_in,
        require_owner, require_csrf, start_oauth,
    )
    return app


app = create_app()

if __name__ == "__main__":
    # Para desenvolvimento local use HTTPS via proxy ou a CLI da Vercel.
    app.run(port=5000, debug=False)
