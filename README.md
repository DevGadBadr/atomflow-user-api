# AtomFlow User API

A Node.js + Express API for user management, meter settings/logs, and tree/settings storage for AtomFlow.

## Overview

- Auth: bcrypt password hashing, JWT issuance on login
- Users: create, list, and preference flags
- Meter settings: add/update/delete via SQL change batches
- Tree/settings: save and retrieve latest structure
- Logs: export meter logs as CSV from DB
- CORS: open to all origins

Tech: Express, PostgreSQL (pg), dotenv, bcrypt, jsonwebtoken, @fast-csv/format, cors.

## Requirements

- Node.js 18+
- PostgreSQL
- Tables (columns referenced by code):
  - `users` — id, username, password_hash, email, role, created_at, mobilenumber, name, location, isloggedin, isrememberme, roles (jsonb), showNodesLocationByDefault, defaultstartwindow, expandSidePanelOnEditMode
  - `treeandsettings` — id, tree (json), settings (json)
  - `meter_settings` — unid, meter_id, isfavourite, ...
  - `mqttmeter` — id, timestamp, msg (json), meterid

## Setup

1) Install dependencies

```bash
npm install
```

2) Configure environment

Copy `.env.example` to `.env` and update values:

```env
DB_USER=postgres
DB_PASSWORD=yourpassword
DB_HOST=127.0.0.1
DB_PORT=5432
DB_NAME=atomflow
DB_NAME2=atomflow_mqtt
JWT_SECRET=replace-with-a-strong-secret
# PORT is optional; server.js currently uses 3003 directly
PORT=3003
```

3) Run the server

```bash
node server.js
```

Listens on http://localhost:3003.

## API Reference

All responses are JSON unless noted. CORS is open for GET/POST/PUT/DELETE.

### Health

- GET `/` → `{ "res": "API IS GOOD" }`
- GET `/sayhello` → `{ "res": "API IS Saying Hello" }`

### Users & Auth

- GET `/getusers`
  - 200: array of users (raw rows from `users`).

- POST `/validateuser`
  - Body: `{ username: string, password: string, rememberme: boolean }`
  - 200 success:
    ```json
    {
      "res": "authorized",
      "user": { /* full user row incl. roles */ },
      "rememberme": true,
      "token": "<jwt>"
    }
    ```
  - 200 failure: `{ "res": "wrong password" }` or `{ "res": "user not found" }`
  - Note: Token expires `1h` if `rememberme` is true, else `10m`.

- POST `/adduser`
  - Required: `username, password, email, mobile`
  - Optional: `name, role, location, roles (object), time`
  - Time parameter:
    - Predefined values: `"Lifetime"`, `"3 days"`, `"1 week"`, `"1 month"`
    - Custom datetime: 14-digit string format `YYYYMMDDHHmmss` (e.g., `"20251225143000"` for Dec 25, 2025 at 14:30:00)
    - Must be a valid future date if using custom datetime
    - Defaults to `"3 days"` if not provided
  - 201: `{ res: "user created", user: { id, username, email, role, created_at } }`
  - 200: `{ res: "email exists" }` or `{ res: "username exists" }`
  - 400: `{ res: "error", message: "Invalid time format: ..." }` for invalid time values
  - 400/500: error objects with `{ res: "error", message: string }`

- GET `/getallusers` (requires authentication & Admin/Platform Developer role)
  - Returns all non-deleted users with their properties including `usertime`
  - 200: `{ res: "users fetched", users: [ { username, name, email, role, location, mobilenumber, usertime, ... } ] }`
  - The `usertime` field contains either predefined values or custom datetime (14-digit format)

### User preferences (GET updates)

- GET `/updateusershowlocation`
  - Query: `username`, `showNodesLocationByDefault`
  - → `{ res: "User updated" }`

- GET `/updateuserdefaultstartwindow`
  - Query: `username`, `defaultstartwindow`
  - → `{ res: "defaultstartwindow updated" }`

- GET `/updateuserexpandSidePanelOnEditMode`
  - Query: `username`, `expandSidePanelOnEditMode`
  - → `{ res: "expandSidePanelOnEditMode updated" }`

- GET `/updatenodeisfavourite`
  - Query: `unid`, `isfavourite`
  - → `{ res: "Node updated" }`

> Note: These change state over GET; consider migrating to POST/PUT for stricter REST semantics.

### Tree & Settings

- POST `/savetreeandsettings`
  - Body: `{ editedTree: any, currentSettings: any }`
  - Effect: `UPDATE treeandsettings SET tree=$1, settings=$2 WHERE id=1`
  - → `{ res: "tree and settings saved" }`

- GET `/gettreeandsettings`
  - → `{ res: "tree and settings fetched", data: <row> }`

- POST `/savetree`
  - Body: `{ changedTree: any }`
  - Effect: `INSERT INTO treeandsettings(tree) VALUES ($1)`
  - → `{ res: "received Tree" }`

- GET `/gettree`
  - Returns latest tree: `{ tree: <json> }`

- GET `/getnodes`
  - Uses latest `treeandsettings.tree.children` to gather all `unid` where node `type === 'meter'`, then returns matching `meter_settings` rows.
  - → `{ res: "nodes fetched", data: [ /* subset of meter_settings */ ] }`

### Meter Settings

- GET `/getallmetersettings`
  - → `{ success: true, settings: [rows], allmeters: ["<meter_id>", ...] }`

- POST `/addnewsettings`
  - Body: `changes` is an array of `[ query: string, values: any[] ]` pairs.
  - Executes each query; responds immediately.
  - → `{ res: "Settings Added" }`

- POST `/updatemetersetting`
  - Body: same `changes` structure as above.
  - → `{ res: "Settings updated" }`

- POST `/deletemetersetting`
  - Body: `unids: string[]`
  - → `{ res: "Settings Deleted", deletedUnids: ["..."] }`

### Meter Logs

- GET `/meterlogfromdb`
  - Reads last 100 rows from `mqttmeter` in secondary DB.
  - → `{ res: "meterlogfromdb", data: [...] }`

- GET `/downloadlog`
  - Query: `metername` (required), `meterid` (required)
  - Builds CSV from `mqttmeter` rows (parsing `msg` json) and returns a file download.
  - 400: missing params; 404: no data.

Example:
```bash
curl -G "http://localhost:3003/downloadlog" \
  --data-urlencode "metername=site-a-meter-12" \
  --data-urlencode "meterid=12" -o site-a-meter-12.csv
```

## Auth notes

- JWT payload: `{ id, email }` with secret `JWT_SECRET`.
- Expiry: `1h` if remember me, else `10m`.
- No JWT verification middleware ships with this code; most endpoints are open.

## Tests

Jest + Supertest scaffolding exists in `__tests__/`. To run:

```bash
npm test
```

Note: Tests expect the Express `app` to be importable. If needed, export `app` from `server.js` (and gate `app.listen` for non-test runs) or adapt tests accordingly.

## Project scripts

- `npm test` — run Jest
- `npm run test:watch` — watch mode

## License

TBD.
