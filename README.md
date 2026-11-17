# PXzx Store — Novo portal preto & branco

Site do zero para a **Vercel**, feito em **Python / Flask**, com tema preto e branco e MongoDB.

## Páginas

- `/` — página inicial responsiva.
- `/migrar` — migração voluntária, verificação do servidor de origem e autorização pelo Discord.
- `/login` — acesso do proprietário via Discord OAuth2.
- `/painel` — visão geral e editor das mensagens de status do bot (coleção `[BOT_ID].custom_status`).
- `/migracao/admin` — lista de contas autorizadas, com botão de adicionar individualmente ao destino.
- `/privacidade` — explicação do tratamento da autorização.
- `/health` — endpoint básico para conferir publicação.

## 1. Publicar no Vercel

1. Extraia este ZIP.
2. Crie um repositório **privado** no GitHub e envie **o conteúdo da pasta** (não o arquivo ZIP).
3. Entre em https://vercel.com/new e importe o repositório.
4. Defina a pasta raiz como a que contém `app.py`, `requirements.txt` e `public/`.
5. A Vercel detecta automaticamente o Flask. **Não configure Build Command ou Output Directory**.
6. Em **Settings → Environment Variables**, configure as variáveis abaixo para **Production**.
7. Faça um novo deploy de produção após editar qualquer variável.

## 2. Variáveis (as mesmas do projeto anterior)

| Nome | Conteúdo |
|---|---|
| `PUBLIC_BASE_URL` | URL https de produção, ex: `https://m-igra-ao.vercel.app`, sem barra ou caminho |
| `DISCORD_CLIENT_ID` | ID da aplicação Discord OAuth2 |
| `DISCORD_CLIENT_SECRET` | Client Secret dessa aplicação |
| `DASHBOARD_OWNER_ID` | ID da conta Discord do dono do painel |
| `BOT_MONGO_URI` | URI MongoDB Atlas (em segredo) |
| `BOT_MONGO_DATABASE` | Nome do banco de dados usado pelo bot |
| `SESSION_SECRET` | Chave aleatória com 32 caracteres ou mais |
| `BOT_ID` | **Opcional**: ID do bot que grava os status, se for diferente do Client ID |
| `MIGRATION_BOT_TOKEN` | Token do bot instalado na origem e no destino |
| `MIGRATION_SOURCE_ID` | ID do servidor original |
| `MIGRATION_SOURCE_NAME` | Nome que o público deve ver para a origem |
| `MIGRATION_DESTINATION_ID` | ID do novo servidor |
| `MIGRATION_DESTINATION_NAME` | Nome que o público deve ver para o destino |
| `MIGRATION_ENCRYPTION_KEY` | Chave Fernet válida (32 bytes em Base64 URL-safe) |

Não envie tokens, `.env` ou senhas para o GitHub nem para outras pessoas.

### Gerar as duas chaves (PowerShell no Windows)

Rode o código uma vez para cada variável `SESSION_SECRET` e `MIGRATION_ENCRYPTION_KEY`:

```powershell
$bytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes)
[Convert]::ToBase64String($bytes).Replace('+', '-').Replace('/', '_')
$rng.Dispose()
```

**IMPORTANTE:** não altere `MIGRATION_ENCRYPTION_KEY` enquanto houver autorizações pendentes: tokens antigos deixarão de ser descriptografáveis. Use outra chave para a sessão.

## 3. OAuth2 do Discord

1. Vá em https://discord.com/developers/applications e escolha sua aplicação.
2. Em **OAuth2 → Redirects**, cadastre exatamente:
   `https://m-igra-ao.vercel.app/auth/discord/callback` (substitua domínio se o seu for outro).
3. Salve o Redirect.
4. Instale o bot desta aplicação nos **dois** servidores. Ele precisa conseguir consultar membros na origem e permitir a entrada no destino; dê a permissão **Criar convite** no destino conforme a documentação da API.
5. O site usa `identify` para login e `identify guilds.join` para a autorização de entrada no destino. **Não pede senha nem coleta credenciais do usuário.**

> Se mudar o domínio da Vercel, altere tanto o `PUBLIC_BASE_URL` quanto o Redirect no Discord.

## 4. Testar

1. Abra `https://seu-dominio.vercel.app/health` para confirmar que o site publicou.
2. Entre em `/login` **com a conta definida em DASHBOARD_OWNER_ID**.
3. Abra `/migracao/admin`: se houver algo faltando, a página mostra **o nome da variável** e o motivo (sem divulgar segredo).
4. Com uma conta que está **no servidor antigo**, visite `/migrar`, marque a autorização e continue pelo Discord.
5. No painel administrativo, confira a conta autorizada e escolha **Adicionar**.
6. Confira a entrada no servidor de destino.

## 5. Detalhes importantes

- O membro escolhe aceitar ou não. A entrada só é solicitada **depois** da autorização individual pelo Discord.
- Os tokens temporários são **criptografados** no banco e usados apenas para adicionar a conta consentida ao destino.
- Cada autorização dura **até 24 horas** e é excluída depois do processamento, cancelamento ou expiração pelo TTL do MongoDB.
- Não há botão de migrar todos nem migração silenciosa.
- O editor de status grava `{_id: "custom_status", names: [...]}` na coleção cujo nome é `BOT_ID` (ou `DISCORD_CLIENT_ID` se `BOT_ID` estiver vazio). O bot precisa ler essa mesma coleção para aplicar as mensagens.
- O link público `/migrar` não exibe erros de configuração internos. Eles só aparecem no painel privado.
- O novo projeto **não lê tokens do site anterior automaticamente**: é preciso manter as mesmas variáveis configuradas no projeto publicado.
- O ambiente local em `http://localhost` não reproduz integralmente o cookie seguro HTTPS. Use `vercel dev` e teste o OAuth no domínio HTTPS publicado.

**Documentação:**

- https://vercel.com/docs/frameworks/backend/flask
- https://vercel.com/docs/environment-variables
- https://docs.discord.com/developers/topics/oauth2
- https://docs.discord.com/developers/resources/guild#add-guild-member
