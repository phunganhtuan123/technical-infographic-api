# Technical Infographic API

Accounts, per-user settings, and the projects that hold saved diagrams for the
[Technical Infographic editor](https://github.com/phunganhtuan123/technical-infographic-ai).

Go · Echo · GORM · PostgreSQL.

## What this service does not do

It never talks to an AI provider. Prompts, attached images and model calls go
straight from the browser to whatever gateway that person connected — the
arrangement described in the editor's `docs/adr-001-client-ai-gateway.md`.

Storing diagrams here does change the original local-first promise, and that is
a deliberate trade: a person who wants their work on more than one machine has
to put it somewhere. What has not changed is that this service cannot read a
prompt, cannot hold a model credential, and cannot generate a diagram on
anyone's behalf. `user_settings` remembers the *origin* of a gateway so nobody
retypes it, and `PUT /v1/me/settings` refuses any value that looks like a key.

## Running it

```sh
cp .env.example .env
docker compose up -d          # Postgres + the API
curl localhost:8080/healthz
```

Without Docker:

```sh
createdb infographic
export DATABASE_URL="postgres://postgres:postgres@localhost:5432/infographic?sslmode=disable"
export JWT_SECRET="something-at-least-thirty-two-characters"
export AUTO_MIGRATE=true      # development only
make run
```

`AUTO_MIGRATE` is a convenience for local work. Production runs the SQL in
`migrations/`, because GORM's AutoMigrate will not rename a column, will not
drop one, and cannot be rolled back — and it cannot express the partial unique
index on `users.email` that stops two accounts claiming one address.

```sh
make migrate-up      # needs golang-migrate
```

## Layout

```
cmd/api            wiring: config, database, routes, graceful shutdown
internal/config    everything from the environment, validated at boot
internal/model     GORM models
internal/database  connection pool, development AutoMigrate
internal/httpx     one error shape for the whole API
internal/auth      argon2id, access and refresh tokens, middleware
internal/user      /me and per-user settings
internal/project   projects, documents, version history
internal/asset     image upload, signed delivery
internal/storage   where bytes live; local disk now, S3 later
migrations         the real schema
```

## API

Everything lives under `/v1`. Sign-in routes are open; the rest needs
`Authorization: Bearer <access token>`.

| Route | Purpose |
| --- | --- |
| `POST /auth/register` | Email and password. Returns an access token, sets the refresh cookie. |
| `POST /auth/login` | Same shape as register. |
| `POST /auth/refresh` | Rotates the refresh cookie, returns a fresh access token. |
| `POST /auth/logout` | Revokes this device's token family. |
| `GET /me`, `PATCH /me` | Profile and linked sign-in methods. |
| `GET /me/settings`, `PUT /me/settings` | Editor preferences and gateway origin. |
| `GET /projects` | Metadata only — never the documents. |
| `POST /projects` | Create, optionally from an exported workspace JSON. |
| `GET`, `PATCH`, `DELETE /projects/:id` | Metadata. Delete is soft. |
| `POST /projects/:id/duplicate` | The editor's Duplicate button. |
| `GET /projects/:id/document` | The diagram, with the version in an `ETag`. |
| `PUT /projects/:id/document` | Save. Needs `If-Match`. |
| `GET /projects/:id/versions` | History. |
| `POST /projects/:id/versions/:v/restore` | Roll forward to an old document. |
| `POST /projects/:id/assets` | Upload an image (multipart, field `file`). |
| `GET /projects/:id/assets` | Images attached to this project. |
| `GET /assets/:id?exp=&sig=` | The image itself. Signature in the URL, no header. |
| `DELETE /assets/:id` | Remove one. |

### Images

An `<img>` tag cannot send an `Authorization` header, so putting uploads behind
the normal middleware would mean no image ever loads. Every upload therefore
comes back with a URL carrying a short-lived HMAC bound to that one asset —
enough to fetch it, useless for anything else, expired within the hour. Forge
the signature or drop it and the answer is `404`.

Uploads are checked by sniffing the first 512 bytes, not by believing the
declared type. SVG is refused: it can carry script, and these files are served
from the API's own origin. Responses go out with `nosniff` and a sandbox CSP.

Storage is local disk today (`ASSET_DIR`). `internal/storage` is a two-method
interface — that is where an S3 or R2 adapter goes when there is more than one
machine.

### Rate limiting

Three layers, each answering a different attack:

| Layer | Default | Stops |
| --- | --- | --- |
| by address, all routes | 300 / min | one address flooding the service |
| by address, `/auth/*` | 20 / min | one machine spraying passwords across accounts |
| by address **and** email, register and login | 5 / 15 min | a focused attack on one account |

The third is keyed on both because either half alone has a hole: by address, an
office behind one NAT shares a budget and a botnet walks past; by email, an
attacker could lock a victim out of their own login. Together neither works.

`refresh` and `logout` are deliberately outside the strict limit — every open
tab calls them on a timer and would trip it.

The counters live in this process. Two instances behind a load balancer each
keep their own tally, so the effective limit doubles. `httpx.Store` is the
interface to swap for Redis before scaling out.

### Two tokens, on purpose

The **access token** is a short-lived JWT checked by signature alone, with no
database round trip — that is what makes every request cheap. The price is that
it cannot be revoked, so it lives fifteen minutes.

The **refresh token** is a random string with no meaning. Only its SHA-256 hash
is stored, so a leaked database gives an attacker nothing usable, and because
every use is a row it can be revoked the moment something looks wrong.

Each rotation keeps the same `family_id`. Presenting a token that was already
rotated away means somebody kept a copy, so the whole family is revoked and
every device on that line is signed out — including the attacker's. The
legitimate user signs in again; the thief cannot.

### Saving without losing work

Two open tabs will otherwise overwrite each other silently. Every save carries
the version it started from:

```http
PUT /v1/projects/{id}/document
If-Match: "7"

{"document": { … }}
```

A stale version comes back as `409` **with the stored document attached**, so
the client can offer *keep mine / take theirs* instead of a dead end. Diagrams
do not merge automatically and pretending otherwise loses work.

## Tests

```sh
make test
```

The Go tests cover password hashing, document summarising, size limits and the
rate-limit windows.
The paths that need a live database — registration, token rotation, reuse
detection, version conflicts, cross-user isolation — were exercised against a
real PostgreSQL 16 instance during development.

## Not built yet

Google and Facebook sign-in, email verification, password reset, and
`project_members` for sharing. The schema already leaves room for all of them.

One loose end worth naming: `MAX_DOCUMENT_BYTES` is 8 MB, which is generous
because the editor still inlines background images as base64. Once it uploads
them through `/assets` instead, bring the cap back down to something like 1 MB —
a diagram that is only structure has no business being larger.
