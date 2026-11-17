from base64 import urlsafe_b64encode
from datetime import timedelta
from hashlib import sha256
import os
import secrets
from time import time
from urllib.parse import urlencode, urlsplit

from flask import Flask, abort, redirect, render_template, request, session, url_for
from pymongo import MongoClient
from pymongo.errors import PyMongoError
import requests
from migration import register_migration


DISCORD = "https://discord.com"
STATUS_DOCUMENT = {"_id": "custom_status"}
REQUIRED = (
    "PUBLIC_BASE_URL",
    "DISCORD_CLIENT_ID",
    "DISCORD_CLIENT_SECRET",
    "DASHBOARD_OWNER_ID",
    "BOT_MONGO_URI",
    "BOT_MONGO_DATABASE",
    "SESSION_SECRET",
)


def create_app(settings=None):
    settings = os.environ if settings is None else settings
    values = {key: settings.get(key, "").strip() for key in REQUIRED}
    app = Flask(__name__, static_folder=None)
    app.config.update(
        SECRET_KEY=values["SESSION_SECRET"] or None,
        SESSION_COOKIE_NAME="__Host-pxzx_dashboard",
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=4),
        SESSION_REFRESH_EACH_REQUEST=False,
        MAX_CONTENT_LENGTH=8192,
    )

    missing = [key for key, value in values.items() if not value]
    base_url = values["PUBLIC_BASE_URL"].rstrip("/")
    bot_id = settings.get("BOT_ID", "").strip() or values["DISCORD_CLIENT_ID"]
    owner_id = values["DASHBOARD_OWNER_ID"]
    invalid = ""
    collection = None
    database = None
    if not missing:
        try:
            base = urlsplit(base_url)
            if (base.scheme != "https" or not base.hostname or base.username is not None
                    or base.path or base.query or base.fragment):
                raise ValueError("PUBLIC_BASE_URL precisa ser o endereço HTTPS do painel.")
            if any(not value.isascii() or not value.isdecimal()
                   for value in (bot_id, owner_id, values["DISCORD_CLIENT_ID"])):
                raise ValueError("Confira os IDs do Discord nas variáveis de ambiente.")
            if len(values["SESSION_SECRET"]) < 32:
                raise ValueError("SESSION_SECRET precisa ter pelo menos 32 caracteres.")
            client = MongoClient(values["BOT_MONGO_URI"], connect=False, serverSelectionTimeoutMS=4500)
            database = client[values["BOT_MONGO_DATABASE"]]
            collection = database[bot_id]
        except ValueError as exc:
            # Evita enviar mensagens de configuração que possam conter segredos.
            known = (
                "PUBLIC_BASE_URL precisa ser o endereço HTTPS do painel.",
                "Confira os IDs do Discord nas variáveis de ambiente.",
                "SESSION_SECRET precisa ter pelo menos 32 caracteres.",
            )
            invalid = str(exc) if str(exc) in known else "Confira a configuração do painel."
        except PyMongoError:
            invalid = "Confira a URL e o nome do banco MongoDB."

    def signed_in():
        return collection is not None and session.get("owner") == owner_id

    def check_form():
        if not signed_in():
            abort(403)
        expected = session.get("csrf", "")
        received = request.form.get("csrf", "")
        if not expected or not secrets.compare_digest(expected.encode(), received.encode()):
            abort(400)

    def render_status(*, error="", submitted=None, saved=False, code=200):
        available = False
        names = []
        try:
            document = collection.find_one(STATUS_DOCUMENT, {"names": 1, "name": 1})
            if document is None:
                error = "Confira se o banco e o ID do bot correspondem à aplicação em execução."
                code = 503
            else:
                available = True
                names = document.get("names")
                if not isinstance(names, list) or not names:
                    names = [document.get("name", "")]
                names = [name for name in names if isinstance(name, str) and name]
        except PyMongoError:
            error, code = "O MongoDB está indisponível. Confira a conexão do painel.", 503
        return render_template(
            "index.html", authenticated=True, ready=True, available=available,
            account=session.get("display_name", "Discord"), csrf=session["csrf"],
            status_text="\n".join(names) if submitted is None else submitted,
            first_status=names[0] if names else "Sem mensagem de status",
            error=error, saved=saved and not error,
        ), code

    @app.after_request
    def protect_response(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'self' https://discord.com"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.get("/health")
    def health():
        return {"status": "ok" if collection is not None else "awaiting_configuration"}

    @app.get("/")
    def home():
        if signed_in():
            return render_status(saved=request.args.get("salvo") == "1")
        return render_template(
            "index.html", authenticated=False, ready=collection is not None,
            error=invalid, needs_setup=bool(missing or invalid),
        )

    def start_discord_login(purpose, scope, context=""):
        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(48)
        challenge = urlsafe_b64encode(sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        session["discord_oauth"] = {
            "state": state, "verifier": verifier, "started": int(time()),
            "purpose": purpose, "context": context,
        }
        parameters = urlencode({
            "response_type": "code", "client_id": values["DISCORD_CLIENT_ID"],
            "redirect_uri": base_url + "/auth/discord/callback", "scope": scope,
            "state": state, "code_challenge": challenge, "code_challenge_method": "S256",
        })
        return redirect(f"{DISCORD}/oauth2/authorize?{parameters}", code=303 if request.method == "POST" else 302)

    @app.get("/login")
    def login():
        if collection is None:
            return redirect(url_for("home"))
        session.clear()
        return start_discord_login("owner", "identify")

    @app.get("/auth/discord/callback")
    def callback():
        if collection is None:
            abort(400)
        oauth = session.pop("discord_oauth", None)
        supplied = request.args.get("state", "")
        if (not oauth or time() - oauth["started"] > 600
                or not secrets.compare_digest(oauth["state"].encode(), supplied.encode())
                or request.args.get("iss", DISCORD) != DISCORD):
            abort(400)
        purpose = oauth["purpose"]
        code = request.args.get("code")
        if purpose != "owner" and request.args.get("error") == "access_denied":
            return redirect(url_for("migration.public_page", notice="declined"), code=303)
        if not code:
            abort(400)
        try:
            grant = requests.post(f"{DISCORD}/api/v10/oauth2/token", data={
                "grant_type": "authorization_code", "client_id": values["DISCORD_CLIENT_ID"],
                "client_secret": values["DISCORD_CLIENT_SECRET"], "code": code,
                "code_verifier": oauth["verifier"], "redirect_uri": base_url + "/auth/discord/callback",
            }, timeout=8, allow_redirects=False)
            if grant.status_code != 200:
                return render_template("error.html", message="Falha no login. Confira o Client Secret e o Redirect."), 502
            grant_data = grant.json()
            token = grant_data["access_token"]
            if not isinstance(token, str) or not token:
                abort(502)
            profile = requests.get(f"{DISCORD}/api/v10/users/@me", headers={
                "Authorization": f"Bearer {token}",
            }, timeout=8, allow_redirects=False)
            if profile.status_code != 200:
                abort(502)
            user = profile.json()
        except (requests.RequestException, KeyError, ValueError, TypeError):
            abort(502)
        if not isinstance(user, dict):
            abort(502)
        if purpose != "owner":
            return finish_migration(purpose, oauth["context"], grant_data, user)
        if user.get("id") != owner_id:
            abort(403)
        session.clear()
        session.permanent = True
        session.update(owner=owner_id, display_name=user.get("global_name") or user.get("username") or "Discord",
                       csrf=secrets.token_urlsafe(32))
        return redirect(url_for("home"))

    @app.post("/status")
    def save_status():
        check_form()
        text = request.form.get("names", "")
        names = [line.strip() for line in text.splitlines() if line.strip()]
        if not 1 <= len(names) <= 5 or any(len(name) > 100 for name in names):
            return render_status(error="Informe de 1 a 5 frases com até 100 caracteres cada.",
                                 submitted=text, code=400)
        try:
            result = collection.update_one(STATUS_DOCUMENT, {"$set": {"names": names}, "$unset": {"name": ""}})
            if not result.matched_count:
                return render_status(error="O documento de status não foi encontrado.", submitted=text, code=503)
        except PyMongoError:
            return render_status(error="O MongoDB não confirmou a alteração. Tente de novo.",
                                 submitted=text, code=503)
        return redirect(url_for("home", salvo="1"), code=303)

    @app.post("/sair")
    def logout():
        check_form()
        session.clear()
        return redirect(url_for("home"), code=303)

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(502)
    def show_error(error):
        messages = {
            400: "Esta tentativa expirou ou é inválida. Volte ao painel e tente de novo.",
            403: "O acesso a este painel é restrito ao proprietário configurado.",
            502: "Não foi possível concluir o login pelo Discord. Tente de novo.",
        }
        return render_template("error.html", message=messages[error.code]), error.code

    finish_migration = register_migration(
        app, settings, database, values["DISCORD_CLIENT_ID"], start_discord_login, signed_in, check_form,
    )
    return app


app = create_app()
