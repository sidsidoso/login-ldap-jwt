# login-ldap-jwt

[![CI](https://github.com/sidsidoso/login-ldap-jwt/actions/workflows/ci.yml/badge.svg)](https://github.com/sidsidoso/login-ldap-jwt/actions/workflows/ci.yml)
[![Node.js](https://img.shields.io/badge/node-%3E%3D20.12-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![Licença: MIT](https://img.shields.io/badge/licen%C3%A7a-MIT-blue.svg)](LICENSE)

API de **login corporativo** em Node.js + Express: o usuário informa login e senha, a API valida as credenciais com um **bind no LDAP** (OpenLDAP ou Active Directory), lê os **grupos** (`memberOf`) e devolve um **JWT** com os **papéis** mapeados a partir desses grupos. Rotas protegidas usam um middleware de autorização por papel.

O repositório inclui um **servidor LDAP fake em memória** (feito com `ldapjs`) para rodar a demo e os testes sem depender de um diretório real.

## Tecnologias

- [Node.js](https://nodejs.org/) ≥ 20.12 (ES Modules, `node:test`, `fetch` nativo)
- [Express 5](https://expressjs.com/) — tratamento nativo de erros em handlers `async`
- [ldapjs 3.0.7](https://github.com/ldapjs/node-ldapjs) — cliente e servidor LDAP
- [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) — emissão e verificação de JWT (HS256)

## Arquitetura

```
 Cliente                API (Express)                         Diretório LDAP
 ───────                ─────────────                         ──────────────
 POST /auth/login ──▶  valida entrada (usuário/senha)
 {usuario, senha}       │
                        ├─ 1. bind conta de serviço ────────▶  OK
                        ├─ 2. search (&(objectClass=person)
                        │       (uid=<valor escapado>)) ─────▶  DN + cn, mail, memberOf
                        ├─ 3. bind DN do usuário + senha ────▶  OK / InvalidCredentials
                        ├─ 4. unbind (sempre, em finally) ───▶
                        ├─ 5. memberOf ─▶ papéis (MAPA_PAPEIS)
                        └─ 6. assina JWT HS256 (exp curta)
 ◀── { token, usuario } ┘

 GET /me  (Authorization: Bearer <jwt>)
   └─ exigirToken (HS256 fixo, iss, aud, exp) ─▶ exigirPapel(...) ─▶ handler
```

Organização em camadas: `rotas` (HTTP) → `servicos` (LDAP e tokens) com `middlewares` para autenticação, autorização, limite de tentativas e erros. O `src/app.js` recebe a configuração e os serviços por **injeção de dependências**, o que deixa a aplicação fácil de testar.

## Endpoints

| Método | Rota                     | Autenticação | Papel exigido             | Descrição                                     |
|--------|--------------------------|--------------|---------------------------|-----------------------------------------------|
| GET    | `/saude`                 | —            | —                         | Verificação de saúde                          |
| POST   | `/auth/login`            | —            | —                         | Autentica no LDAP e devolve o JWT             |
| GET    | `/me`                    | Bearer JWT   | qualquer                  | Perfil do usuário autenticado (lido do token) |
| GET    | `/admin/painel`          | Bearer JWT   | `admin`                   | Exemplo de rota administrativa                |
| GET    | `/financeiro/relatorios` | Bearer JWT   | `financeiro` ou `admin`   | Exemplo de rota com mais de um papel          |

Erros sempre em JSON: `400` (entrada inválida/JSON malformado), `401` (credenciais ou token inválidos), `403` (sem o papel), `404`, `413` (corpo > 100 kB), `429` (muitas tentativas), `503` (LDAP indisponível).

### Usuários do servidor LDAP fake

| Usuário        | Senha        | Grupos                        | Papéis no JWT            |
|----------------|--------------|-------------------------------|--------------------------|
| `ana.souza`    | `Ana@2026`   | `ti-admins`, `colaboradores`  | `admin`, `usuario`       |
| `bruno.lima`   | `Bruno@2026` | `financeiro`, `colaboradores` | `financeiro`, `usuario`  |
| `carla.mendes` | `Carla@2026` | `colaboradores`               | `usuario`                |

## Exemplos (saídas reais)

Login:

```bash
curl -s -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"usuario":"ana.souza","senha":"Ana@2026"}'
```

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJub21lIjoiQW5hIFNvdXphIiwiZW1haWwiOiJhbmEuc291emFAZW1wcmVzYS5sb2NhbCIsInBhcGVpcyI6WyJhZG1pbiIsInVzdWFyaW8iXSwiaWF0IjoxNzkzOTA3MTgwLCJleHAiOjE3OTM5MDgwODAsImF1ZCI6ImFwaXMtaW50ZXJuYXMiLCJpc3MiOiJsb2dpbi1sZGFwLWp3dCIsInN1YiI6ImFuYS5zb3V6YSJ9.m2WsplqxqXazusUw0jnix_Pvc6MYdEn97BK_APrcwzM",
  "tipo": "Bearer",
  "expiraEm": "15m",
  "usuario": {
    "usuario": "ana.souza",
    "nome": "Ana Souza",
    "email": "ana.souza@empresa.local",
    "grupos": ["ti-admins", "colaboradores"],
    "papeis": ["admin", "usuario"]
  }
}
```

Payload do token emitido (decodificado):

```json
{
  "nome": "Ana Souza",
  "email": "ana.souza@empresa.local",
  "papeis": ["admin", "usuario"],
  "iat": 1793907180,
  "exp": 1793908080,
  "aud": "apis-internas",
  "iss": "login-ldap-jwt",
  "sub": "ana.souza"
}
```

Perfil e rota com papel:

```bash
curl -s http://localhost:3000/me -H "Authorization: Bearer $TOKEN"
# {"usuario":"ana.souza","nome":"Ana Souza","email":"ana.souza@empresa.local","papeis":["admin","usuario"],"expiraEm":"2026-11-05T19:48:00.000Z"}

curl -s http://localhost:3000/admin/painel -H "Authorization: Bearer $TOKEN"
# {"mensagem":"Bem-vindo(a) ao painel administrativo, Ana Souza"}
```

Casos de erro:

```bash
# senha errada (a resposta é idêntica para usuário inexistente)
curl -s -X POST http://localhost:3000/auth/login -H "Content-Type: application/json" \
  -d '{"usuario":"ana.souza","senha":"errada"}'
# {"erro":"Usuário ou senha inválidos"}

# usuária sem o papel "admin"
curl -s -i http://localhost:3000/admin/painel -H "Authorization: Bearer $TOKEN_CARLA"
# HTTP/1.1 403 Forbidden
# {"erro":"Acesso negado para o seu perfil"}

# sem token
curl -s http://localhost:3000/me
# {"erro":"Token ausente"}

# tentativa de injeção no filtro LDAP
curl -s -X POST http://localhost:3000/auth/login -H "Content-Type: application/json" \
  -d '{"usuario":"*","senha":"x"}'
# {"erro":"Campo \"usuario\" inválido"}
```

> No Windows (PowerShell), use `curl.exe` ou `Invoke-RestMethod`, por exemplo:
> `Invoke-RestMethod -Method Post -Uri http://localhost:3000/auth/login -ContentType 'application/json' -Body '{"usuario":"ana.souza","senha":"Ana@2026"}'`

## Decisões de implementação, otimizações e segurança

- **Busca + bind (search-then-bind):** a conta de serviço localiza o DN pelo atributo de login (`uid` ou `sAMAccountName`), e só então é feito o bind com a senha do usuário. A API nunca monta DNs a partir da entrada do usuário.
- **Escape de filtros LDAP (RFC 4515):** `*`, `(`, `)`, `\` e NUL são escapados (`\2a`, `\28`...), o que impede LDAP injection. Além disso, a rota valida o formato do usuário. Há testes cobrindo as duas camadas.
- **Senha vazia é recusada:** muitos servidores tratam bind com senha vazia como *bind não autenticado* e respondem sucesso; a validação impede esse bypass clássico.
- **Uma conexão por login, reaproveitada:** a mesma conexão faz o bind de serviço, a busca e o rebind do usuário, e é sempre encerrada com `unbind` em um bloco `finally`. Não há pool porque o rebind altera a identidade da conexão.
- **Timeouts** de conexão e de operação (`LDAP_TIMEOUT_MS`) e `sizeLimit: 2` na busca: se o login casar com mais de um registro, o acesso é negado.
- **Mensagem única para falhas de credencial** (usuário inexistente ou senha errada), evitando enumeração de usuários.
- **JWT:** `HS256` **fixado na verificação** (bloqueia `alg: none` e troca de algoritmo), validação de `iss`/`aud`, expiração curta (padrão 15 min) e segredo de no mínimo 32 caracteres vindo de variável de ambiente; o servidor não sobe sem ele.
- **Limite de tentativas** de login por IP (janela fixa, em memória) com `Retry-After`.
- **Express endurecido:** `x-powered-by` desabilitado, `express.json({ limit: '100kb' })`, 404 e erros centralizados em JSON; os logs nunca incluem o corpo da requisição (senhas).
- `/me` responde a partir do próprio token, sem nova ida ao LDAP.

## Como rodar

Pré-requisitos: Node.js 20.12 ou superior e npm.

```bash
git clone https://github.com/sidsidoso/login-ldap-jwt.git
cd login-ldap-jwt
npm install
```

Configure o ambiente copiando o exemplo (o `server.js` carrega o `.env` automaticamente):

```bash
# Linux/macOS
cp .env.example .env
```

```powershell
# Windows (PowerShell)
Copy-Item .env.example .env
```

Em dois terminais:

```bash
npm run ldap:fake   # terminal 1: servidor LDAP fake em ldap://127.0.0.1:1389
npm start           # terminal 2: API em http://localhost:3000
```

Use `npm run dev` para reiniciar automaticamente ao salvar (`node --watch`).

Para um diretório real, ajuste `LDAP_URL` (prefira `ldaps://`), `LDAP_BASE_USUARIOS`, `LDAP_BIND_DN`, `LDAP_BIND_SENHA` e, no Active Directory, `LDAP_ATRIBUTO_LOGIN=sAMAccountName`. O mapeamento de grupos para papéis fica em `MAPA_PAPEIS` (JSON `{"cn-do-grupo":"papel"}`).

| Variável               | Padrão                                         | Descrição                               |
|------------------------|------------------------------------------------|-----------------------------------------|
| `PORTA`                | `3000`                                         | Porta HTTP                              |
| `LDAP_URL`             | `ldap://127.0.0.1:1389`                        | URL do servidor LDAP                    |
| `LDAP_BASE_USUARIOS`   | `ou=usuarios,dc=empresa,dc=local`              | Base da busca de usuários               |
| `LDAP_BIND_DN`         | `cn=svc-login,ou=servicos,dc=empresa,dc=local` | DN da conta de serviço                  |
| `LDAP_BIND_SENHA`      | —                                              | Senha da conta de serviço (obrigatória) |
| `LDAP_ATRIBUTO_LOGIN`  | `uid`                                          | `uid` ou `sAMAccountName`               |
| `LDAP_TIMEOUT_MS`      | `5000`                                         | Timeout de conexão e operações          |
| `JWT_SEGREDO`          | —                                              | Segredo HS256 (≥ 32 caracteres)         |
| `JWT_EXPIRA_EM`        | `15m`                                          | Validade do token                       |
| `JWT_EMISSOR` / `JWT_AUDIENCIA` | `login-ldap-jwt` / `apis-internas`    | Claims `iss` e `aud`                    |
| `MAPA_PAPEIS`          | ver `.env.example`                             | Grupo → papel                           |
| `LOGIN_MAX_TENTATIVAS` / `LOGIN_JANELA_MS` | `10` / `900000`            | Limite de tentativas por IP             |

## Testes

```bash
npm test
```

Os testes (`node:test` + `node:assert/strict` + `fetch`) sobem o servidor LDAP fake e a API em **portas aleatórias (porta 0)**, então não conflitam com nada que esteja rodando. Funcionam igual no Windows, Linux e macOS. Cobrem: login válido e inválido, papéis no token, escape de filtro, senha vazia, JSON malformado, `/me`, autorização por papel (403), token expirado e `alg: none`, 404, LDAP fora do ar (503) e limite de tentativas (429).

```
ℹ tests 21
ℹ suites 4
ℹ pass 21
ℹ fail 0
```

## Estrutura de pastas

```
login-ldap-jwt/
├── .github/workflows/ci.yml        # CI: Node 20 e 22
├── scripts/
│   └── servidor-ldap-fake.js       # servidor LDAP em memória (demo/testes)
├── src/
│   ├── app.js                      # monta o Express (injeção de dependências)
│   ├── server.js                   # ponto de entrada (carrega .env, sobe a API)
│   ├── config.js                   # variáveis de ambiente
│   ├── middlewares/
│   │   ├── autenticacao.js         # exigirToken e exigirPapel
│   │   ├── erros.js                # ErroHttp, 404 e tratador central
│   │   └── limiteTentativas.js     # limite de tentativas por IP
│   ├── rotas/
│   │   ├── auth.js                 # POST /auth/login
│   │   └── protegidas.js           # /me, /admin/painel, /financeiro/relatorios
│   └── servicos/
│       ├── autenticacao.js         # search-then-bind, grupos → papéis
│       ├── ldap.js                 # helpers do ldapjs (Promises, escape, unbind)
│       └── tokens.js               # emissão/verificação de JWT
├── tests/
│   ├── api.test.js
│   └── unitarios.test.js
├── .env.example
└── LICENSE
```

## Observações

- O pacote **`ldapjs` foi descontinuado pelos mantenedores** (o npm o marca como *deprecated*). Ele foi usado aqui por ser a referência clássica de cliente **e** servidor LDAP em Node.js, o que permite o servidor fake. Para projetos novos em produção, considere o [`ldapts`](https://github.com/ldapts/ldapts) (cliente mantido, com Promises e TypeScript).
- O servidor fake é só para desenvolvimento: guarda senhas em memória e não usa TLS. Em produção, use `ldaps://` (ou StartTLS) para que a senha não trafegue em texto puro.
- O limitador de tentativas é em memória; com várias instâncias da API, use um armazenamento compartilhado.

## Referências

- [RFC 4511 — LDAP: The Protocol](https://www.rfc-editor.org/rfc/rfc4511)
- [RFC 4515 — LDAP: String Representation of Search Filters](https://www.rfc-editor.org/rfc/rfc4515)
- [RFC 7519 — JSON Web Token](https://www.rfc-editor.org/rfc/rfc7519) e [RFC 8725 — JWT Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725)
- [OWASP — LDAP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html)
- [Documentação do ldapjs](http://ldapjs.org/)
- [Express 5 — guia de migração](https://expressjs.com/en/guide/migrating-5.html)

## Licença

[MIT](LICENSE) © 2026 sidsidoso
