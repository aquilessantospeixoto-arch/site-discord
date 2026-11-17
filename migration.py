"""Rotas de migração com consentimento explícito, token cifrado e expiração."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import secrets

from cryptography.fernet import Fernet, InvalidToken
from flask import Blueprint, abort, redirect, render_template, request, session, url_for
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError, PyMongoError
import requests

API = "https://discord.com/api/v10"
PAGE_SIZE = 25
PUBLIC_MESSAGES = {
    "authorized": "Autorização registrada! A equipe poderá adicionar sua conta ao servidor de destino.",
    "declined": "Você cancelou a autorização no Discord. Nenhum acesso foi registrado.",
    "canceled": "Autorização cancelada e removida.",
    "not_member": "Esta conta não faz parte do servidor de origem.",
    "locked": "Esta autorização está sendo processada. Atualize a página em instantes.",
    "denied": "O Discord não confirmou a permissão necessária.",
    "unavailable": "Serviço temporariamente indisponível. Tente novamente mais tarde.",
}
ADMIN_MESSAGES = {
    "joined": "O Discord confirmou a entrada no servidor de destino.",
    "present": "Esse membro já está no destino. A autorização foi removida.",
    "expired": "O token expirou. Peça ao membro para autorizar novamente.",
    "missing": "Esta autorização não existe, expirou ou já foi usada.",
    "permissions": "Discord negou acesso. Confira o bot, os IDs e suas permissões no destino.",
    "limited": "Limite de solicitações do Discord atingido. Tente mais tarde.",
    "unavailable": "Discord ou MongoDB indisponível. Confira antes de repetir a operação.",
    "rejected": "A entrada não foi aceita. Confira as regras e condições da conta no Discord.",
}


def now_utc():
    return datetime.now(timezone.utc)


def snowflake(value):
    return (isinstance(value, str) and value.isascii() and value.isdecimal()
            and 1 <= len(value) <= 20 and value[0] != "0" and int(value) < 2**64)


def discord_error(response):
    try:
        return response.json().get("code")
    except (ValueError, AttributeError):
        return None


def setup_migration(app, env, db, client_id, core_errors, owner_logged_in,
                    require_owner, require_csrf, start_oauth):
    bp = Blueprint("migration", __name__)
    fields = ["MIGRATION_BOT_TOKEN", "MIGRATION_SOURCE_ID", "MIGRATION_SOURCE_NAME",
              "MIGRATION_DESTINATION_ID", "MIGRATION_DESTINATION_NAME", "MIGRATION_ENCRYPTION_KEY"]
    config = {k: str(env.get(k, "")).strip() for k in fields}
    src = config["MIGRATION_SOURCE_ID"]
    dst = config["MIGRATION_DESTINATION_ID"]
    problems = list(core_errors)
    for field in fields:
        if not config[field]:
            problems.append(f"{field}: variável não configurada.")
    for field in ("MIGRATION_SOURCE_ID", "MIGRATION_DESTINATION_ID"):
        if config[field] and not snowflake(config[field]):
            problems.append(f"{field}: ID numérico inválido.")
    if src and src == dst:
        problems.append("Os servidores de origem e destino devem ser diferentes.")
    try:
        cipher = Fernet(config["MIGRATION_ENCRYPTION_KEY"].encode())
    except (ValueError, TypeError):
        cipher = None
        if config["MIGRATION_ENCRYPTION_KEY"]:
            problems.append("MIGRATION_ENCRYPTION_KEY: a chave precisa ser Fernet (32 bytes, Base64 URL-safe).")
    if db is None:
        if not any("Mongo" in issue or "BOT_MONGO" in issue for issue in problems):
            problems.append("MongoDB não está configurado corretamente.")
    ready = not problems
    consents = db["discord_migration_consents"] if ready else None
    campaign = f"{client_id}:{src}:{dst}"

    def doc_id(user_id):
        return f"{campaign}:{user_id}"

    def member_id():
        identity = session.get("member_identity") or {}
        return identity.get("user_id") if identity.get("campaign") == campaign else None

    def member_csrf():
        expected = session.get("csrf_token", "")
        received = request.form.get("csrf_token", "")
        if not expected or not received or not secrets.compare_digest(expected, received):
            abort(400)

    def public_notice(message):
        return redirect(url_for("migration.migrate", msg=message), code=303)

    def admin_notice(message):
        return redirect(url_for("migration.admin", msg=message), code=303)

    def available(at):
        return {"$or": [{"processing_until": {"$exists": False}},
                        {"processing_until": {"$lte": at}}]}

    @bp.get("/migrar")
    def migrate():
        current = None
        info = PUBLIC_MESSAGES.get(request.args.get("msg"))
        if ready and member_id():
            try:
                current = consents.find_one({"_id": doc_id(member_id()),
                                             "expires_at": {"$gt": now_utc()}},
                                            {"expires_at": 1})
            except PyMongoError:
                info = PUBLIC_MESSAGES["unavailable"]
        return render_template("migration.html", ready=ready,
                               source=config["MIGRATION_SOURCE_NAME"], source_id=src,
                               destination=config["MIGRATION_DESTINATION_NAME"], destination_id=dst,
                               consent=current, identified=bool(member_id()), notice=info)

    @bp.post("/migrar/autorizar")
    def authorize():
        if not ready:
            abort(503)
        member_csrf()
        if request.form.get("consent") != "yes":
            abort(400)
        return start_oauth("member_consent", "identify guilds.join", campaign)

    @bp.post("/migrar/consultar")
    def review():
        if not ready:
            abort(503)
        member_csrf()
        return start_oauth("member_lookup", "identify", campaign)

    @bp.post("/migrar/cancelar")
    def cancel():
        if not ready:
            abort(503)
        member_csrf()
        user_id = member_id()
        if not user_id:
            abort(403)
        at = now_utc()
        try:
            delete = consents.delete_one({"_id": doc_id(user_id), **available(at)})
            if delete.deleted_count == 0 and consents.find_one({"_id": doc_id(user_id)}, {"_id": 1}):
                return public_notice("locked")
        except PyMongoError:
            return public_notice("unavailable")
        return public_notice("canceled")

    @bp.get("/migracao/admin")
    def admin():
        require_owner()
        cursor = request.args.get("depois", "")
        if cursor and not snowflake(cursor):
            abort(400)
        people = []
        notice = ADMIN_MESSAGES.get(request.args.get("msg"))
        count = None
        if ready:
            query = {"campaign": campaign, "expires_at": {"$gt": now_utc()}}
            if cursor:
                query["_id"] = {"$gt": doc_id(cursor)}
            try:
                people = list(consents.find(query, {"user_id": 1, "name": 1, "expires_at": 1})
                              .sort("_id", 1).limit(PAGE_SIZE + 1))
                count = consents.count_documents({"campaign": campaign,
                                                  "expires_at": {"$gt": now_utc()}})
            except PyMongoError:
                notice = ADMIN_MESSAGES["unavailable"]
        next_cursor = people[PAGE_SIZE - 1]["user_id"] if len(people) > PAGE_SIZE else None
        return render_template("migration_admin.html", section="migration", ready=ready,
                               config_errors=problems, source=config["MIGRATION_SOURCE_NAME"],
                               destination=config["MIGRATION_DESTINATION_NAME"], people=people[:PAGE_SIZE],
                               pending=count, next_cursor=next_cursor, cursor=cursor, notice=notice)

    @bp.post("/migracao/admin/adicionar")
    def add():
        require_owner()
        require_csrf()
        user_id = request.form.get("user_id", "")
        if not ready or not snowflake(user_id):
            abort(400)
        key = doc_id(user_id)
        claim = secrets.token_urlsafe(20)
        now = now_utc()
        try:
            entry = consents.find_one_and_update({"_id": key,
                                                  "expires_at": {"$gt": now},
                                                  **available(now)},
                                                 {"$set": {"claim": claim,
                                                           "processing_until": now + timedelta(seconds=45)}},
                                                 projection={"token": 1},
                                                 return_document=ReturnDocument.AFTER)
        except PyMongoError:
            return admin_notice("unavailable")
        if entry is None:
            return admin_notice("missing")

        claimed = {"_id": key, "claim": claim}
        outcome = "rejected"
        try:
            token = cipher.decrypt(entry["token"].encode()).decode()
            response = requests.put(f"{API}/guilds/{dst}/members/{user_id}",
                                    headers={"Authorization": f"Bot {config['MIGRATION_BOT_TOKEN']}"},
                                    json={"access_token": token}, timeout=(4, 8),
                                    allow_redirects=False)
            if response.status_code == 201:
                outcome = "joined"
            elif response.status_code == 204:
                outcome = "present"
            elif response.status_code == 429:
                outcome = "limited"
            elif response.status_code in (401, 403):
                outcome = "permissions"
            elif discord_error(response) in (50025, 10012):
                outcome = "expired"
            elif response.status_code >= 500:
                outcome = "unavailable"
        except InvalidToken:
            outcome = "expired"
        except (requests.RequestException, ValueError, KeyError):
            outcome = "unavailable"

        try:
            if outcome in ("joined", "present", "expired"):
                consents.delete_one(claimed)
            else:
                consents.update_one(claimed, {"$unset": {"claim": "", "processing_until": ""}})
        except PyMongoError:
            outcome = "unavailable"
        return admin_notice(outcome)

    def complete_oauth(purpose, context, grant, profile):
        if not ready or context != campaign or not snowflake(profile.get("id", "")):
            abort(400)
        user_id = profile["id"]
        session["member_identity"] = {"campaign": campaign, "user_id": user_id}
        if purpose == "member_lookup":
            return public_notice(None)
        if purpose != "member_consent":
            abort(400)
        granted = str(grant.get("scope", "")).split()
        expires_in = grant.get("expires_in")
        if "guilds.join" not in granted or type(expires_in) is not int or expires_in <= 0:
            return public_notice("denied")
        try:
            check = requests.get(f"{API}/guilds/{src}/members/{user_id}",
                                 headers={"Authorization": f"Bot {config['MIGRATION_BOT_TOKEN']}"},
                                 timeout=(4, 8), allow_redirects=False)
        except requests.RequestException:
            return public_notice("unavailable")
        if check.status_code == 404 and discord_error(check) == 10007:
            return public_notice("not_member")
        if check.status_code != 200:
            return public_notice("unavailable")

        label = profile.get("global_name") or profile.get("username") or "Usuário Discord"
        timestamp = now_utc()
        try:
            consents.create_index("expires_at", expireAfterSeconds=0)
            consents.update_one({"_id": doc_id(user_id), **available(timestamp)},
                                {"$set": {"user_id": user_id, "campaign": campaign,
                                          "name": str(label)[:100],
                                          "token": cipher.encrypt(grant["access_token"].encode()).decode(),
                                          "expires_at": timestamp + timedelta(seconds=min(expires_in, 86400))},
                                 "$unset": {"claim": "", "processing_until": ""}}, upsert=True)
        except (PyMongoError, DuplicateKeyError, KeyError, TypeError):
            return public_notice("unavailable")
        return public_notice("authorized")

    app.register_blueprint(bp)
    return complete_oauth, ready, campaign, now_utc
