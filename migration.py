from datetime import datetime, timedelta, timezone
import secrets

from cryptography.fernet import Fernet, InvalidToken
from flask import Blueprint, abort, redirect, render_template, request, session, url_for
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError, PyMongoError
import requests


API = "https://discord.com/api/v10"
PAGE_SIZE = 30
PUBLIC_NOTICES = {
    "authorized": "Autorização registrada. Agora a equipe pode adicionar você ao destino.",
    "canceled": "Sua autorização de entrada foi cancelada.",
    "declined": "A autorização pelo Discord foi cancelada.",
    "not_member": "A conta precisa fazer parte do servidor de origem para autorizar a migração.",
    "locked": "A entrada já começou a ser processada. Confira de novo em instantes.",
    "discord": "O Discord não confirmou a autorização. Tente novamente.",
    "unavailable": "A migração está temporariamente indisponível. Avise a equipe do servidor.",
}
ADMIN_NOTICES = {
    "joined": "O Discord confirmou a entrada no servidor de destino.",
    "present": "A conta já está no servidor de destino.",
    "unavailable": "Não foi possível confirmar o resultado. Confira no Discord antes de tentar de novo.",
    "missing": "A autorização expirou, foi cancelada ou já está em processamento.",
    "expired": "Esta autorização não pode mais ser usada. O membro poderá autorizar novamente.",
    "limited": "O Discord limitou as solicitações. Aguarde e tente de novo.",
    "permissions": "Confira o token, a instalação do bot no destino e a permissão de criar convites.",
    "rejected": "O Discord recusou a entrada. Confira o acesso dessa conta ao servidor de destino.",
}


def now_utc():
    return datetime.now(timezone.utc)


def is_discord_id(value):
    return (
        isinstance(value, str) and 1 <= len(value) <= 20 and value.isascii()
        and value.isdecimal() and value[0] != "0" and int(value) < 2**64
    )


def discord_error_code(response):
    try:
        return response.json().get("code")
    except (ValueError, AttributeError):
        return None


def register_migration(app, settings, database, client_id, start_login, signed_in, check_owner_form):
    migration = Blueprint("migration", __name__)
    source_id = settings.get("MIGRATION_SOURCE_ID", "").strip()
    destination_id = settings.get("MIGRATION_DESTINATION_ID", "").strip()
    source_name = settings.get("MIGRATION_SOURCE_NAME", "").strip()
    destination_name = settings.get("MIGRATION_DESTINATION_NAME", "").strip()
    token = settings.get("MIGRATION_BOT_TOKEN", "").strip()
    encryption_key = settings.get("MIGRATION_ENCRYPTION_KEY", "").strip()
    try:
        fernet = Fernet(encryption_key.encode())
    except (ValueError, TypeError):
        fernet = None

    # Only show field names and safe validation messages to the authenticated owner.
    # Never render environment variable values or secrets in the page.
    config_problems = []
    if database is None:
        config_problems.append("MongoDB do painel indisponível: confira BOT_MONGO_URI, BOT_MONGO_DATABASE e as variáveis gerais do painel.")
    if not token:
        config_problems.append("MIGRATION_BOT_TOKEN não foi definida ou está vazia.")
    if not source_name:
        config_problems.append("MIGRATION_SOURCE_NAME não foi definida ou está vazia.")
    if not destination_name:
        config_problems.append("MIGRATION_DESTINATION_NAME não foi definida ou está vazia.")
    if not is_discord_id(source_id):
        config_problems.append("MIGRATION_SOURCE_ID está ausente ou não é um ID numérico válido do Discord.")
    if not is_discord_id(destination_id):
        config_problems.append("MIGRATION_DESTINATION_ID está ausente ou não é um ID numérico válido do Discord.")
    if is_discord_id(source_id) and source_id == destination_id:
        config_problems.append("MIGRATION_SOURCE_ID e MIGRATION_DESTINATION_ID precisam ser diferentes.")
    if fernet is None:
        config_problems.append("MIGRATION_ENCRYPTION_KEY está ausente ou não é uma chave Fernet válida (32 bytes em Base64 URL-safe).")
    ready = not config_problems
    app.logger.info("Migração: %s", "configuração pronta" if ready else "verifique configuração no painel administrativo")
    campaign = f"{client_id}:{source_id}:{destination_id}"
    authorizations = database["discord_migration_consents"] if ready else None
    bot_headers = {"Authorization": f"Bot {token}"}

    def record_id(user_id):
        return campaign + ":" + user_id

    def public_notice(notice=None):
        return redirect(url_for("migration.public_page", notice=notice), code=303)

    def admin_notice(notice):
        return redirect(url_for("migration.admin_page", notice=notice), code=303)

    def current_member():
        identity = session.get("migration_identity") or {}
        return identity.get("id") if identity.get("campaign") == campaign else None

    def check_member_form():
        expected = session.get("migration_csrf", "")
        supplied = request.form.get("csrf", "")
        if not expected or not secrets.compare_digest(expected.encode(), supplied.encode()):
            abort(400)

    def unlocked(at):
        return {"$or": [{"locked_until": {"$exists": False}}, {"locked_until": {"$lte": at}}]}

    @migration.get("/migrar")
    def public_page():
        authorization = None
        notice = PUBLIC_NOTICES.get(request.args.get("notice"))
        csrf = None
        if ready:
            csrf = session.setdefault("migration_csrf", secrets.token_urlsafe(32))
            if member := current_member():
                try:
                    authorization = authorizations.find_one(
                        {"_id": record_id(member), "expires_at": {"$gt": now_utc()}},
                        {"expires_at": 1},
                    )
                except PyMongoError:
                    notice = PUBLIC_NOTICES["unavailable"]
        return render_template(
            "migration.html", ready=ready, source_id=source_id, source_name=source_name,
            destination_id=destination_id, destination_name=destination_name, notice=notice,
            csrf=csrf, authorization=authorization, identified=bool(current_member()),
        )

    @migration.post("/migrar/autorizar")
    def authorize():
        if not ready:
            abort(400)
        check_member_form()
        if request.form.get("consent") != "yes":
            abort(400)
        return start_login("migration_consent", "identify guilds.join", campaign)

    @migration.post("/migrar/consultar")
    def identify():
        if not ready:
            abort(400)
        check_member_form()
        return start_login("migration_identity", "identify", campaign)

    @migration.post("/migrar/cancelar")
    def cancel():
        if not ready or not (member := current_member()):
            abort(403)
        check_member_form()
        query = {"_id": record_id(member)}
        try:
            canceled = authorizations.delete_one({**query, **unlocked(now_utc())})
            if canceled.deleted_count == 0 and authorizations.find_one(query, {"_id": 1}):
                return public_notice("locked")
        except PyMongoError:
            return public_notice("unavailable")
        return public_notice("canceled")

    @migration.get("/migracao/admin")
    def admin_page():
        if not signed_in():
            abort(403)
        cursor = request.args.get("depois", "")
        if cursor and not is_discord_id(cursor):
            abort(400)
        entries = []
        notice = ADMIN_NOTICES.get(request.args.get("notice"))
        if ready:
            query = {"campaign": campaign, "expires_at": {"$gt": now_utc()}}
            if cursor:
                query["_id"] = {"$gt": record_id(cursor)}
            try:
                entries = list(authorizations.find(
                    query, {"user_id": 1, "name": 1, "expires_at": 1},
                ).sort("_id", 1).limit(PAGE_SIZE + 1))
            except PyMongoError:
                notice = ADMIN_NOTICES["unavailable"]
        next_cursor = entries[PAGE_SIZE - 1]["user_id"] if len(entries) > PAGE_SIZE else None
        return render_template(
            "migration_admin.html", authenticated=True, account=session.get("display_name", "Discord"),
            csrf=session["csrf"], ready=ready, source_name=source_name,
            destination_name=destination_name, entries=entries[:PAGE_SIZE],
            cursor=cursor, next_cursor=next_cursor, notice=notice, config_problems=config_problems,
        )

    @migration.post("/migracao/admin/adicionar")
    def add_member():
        check_owner_form()
        user_id = request.form.get("user_id")
        if not ready or not is_discord_id(user_id):
            abort(400)
        key = record_id(user_id)
        claim = secrets.token_urlsafe(18)
        now = now_utc()
        try:
            record = authorizations.find_one_and_update(
                {"_id": key, "expires_at": {"$gt": now}, **unlocked(now)},
                {"$set": {"claim": claim, "locked_until": now + timedelta(seconds=45)}},
                projection={"token": 1}, return_document=ReturnDocument.AFTER,
            )
        except PyMongoError:
            return admin_notice("unavailable")
        if not record:
            return admin_notice("missing")

        claimed = {"_id": key, "claim": claim}
        try:
            access_token = fernet.decrypt(record["token"].encode()).decode()
            response = requests.put(
                f"{API}/guilds/{destination_id}/members/{user_id}",
                headers=bot_headers, json={"access_token": access_token},
                timeout=(3, 7), allow_redirects=False,
            )
            if response.status_code in (201, 204):
                result = "joined" if response.status_code == 201 else "present"
            elif discord_error_code(response) == 50025:
                result = "expired"
            elif response.status_code == 429:
                result = "limited"
            elif response.status_code in (401, 403):
                result = "permissions"
            elif response.status_code >= 500:
                result = "unavailable"
            else:
                result = "rejected"
        except InvalidToken:
            result = "expired"
        except requests.RequestException:
            result = "unavailable"

        try:
            if result in ("joined", "present", "expired"):
                authorizations.delete_one(claimed)
            else:
                authorizations.update_one(claimed, {"$unset": {"claim": "", "locked_until": ""}})
        except PyMongoError:
            return admin_notice("unavailable")
        return admin_notice(result)

    def finish_login(purpose, context, grant, user):
        user_id = user.get("id")
        if not ready or context != campaign or not is_discord_id(user_id):
            abort(400)
        session["migration_identity"] = {"campaign": campaign, "id": user_id}
        if purpose == "migration_identity":
            return public_notice()
        if purpose != "migration_consent":
            abort(400)
        expires_in = grant.get("expires_in")
        scope = grant.get("scope")
        if (not isinstance(scope, str) or "guilds.join" not in scope.split()
                or type(expires_in) is not int or expires_in <= 0):
            return public_notice("discord")
        try:
            membership = requests.get(
                f"{API}/guilds/{source_id}/members/{user_id}",
                headers=bot_headers, timeout=(3, 7), allow_redirects=False,
            )
        except requests.RequestException:
            return public_notice("unavailable")
        if membership.status_code == 404 and discord_error_code(membership) == 10007:
            return public_notice("not_member")
        if membership.status_code != 200:
            return public_notice("unavailable")

        now = now_utc()
        display_name = user.get("global_name") or user.get("username")
        try:
            authorizations.create_index("expires_at", expireAfterSeconds=0)
            authorizations.update_one(
                {"_id": record_id(user_id), **unlocked(now)},
                {"$set": {
                    "user_id": user_id, "campaign": campaign,
                    "name": display_name[:100] if isinstance(display_name, str) else "Conta Discord",
                    "token": fernet.encrypt(grant["access_token"].encode()).decode(),
                    "expires_at": now + timedelta(seconds=expires_in),
                }, "$unset": {"claim": "", "locked_until": ""}},
                upsert=True,
            )
        except DuplicateKeyError:
            return public_notice("locked")
        except PyMongoError:
            return public_notice("unavailable")
        return public_notice("authorized")

    app.register_blueprint(migration)
    return finish_login
