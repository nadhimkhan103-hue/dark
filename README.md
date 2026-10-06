# IR EN DARK — Form 05

Browser-based cyber-security community website/web app. **Website / Web App only** — no Android, iOS, APK, or native mobile application.

## Form 05 additions
- Real database-backed posts, comments and reactions retained from the existing system.
- Server-Sent Events (SSE) realtime layer over the existing Express server for community messages, comments and reaction updates.
- Authenticated `fetch()` streaming is used for realtime connections, so visitor JWTs are not placed in EventSource URLs.
- Automatic reconnect and low-frequency database polling fallback for deployments where streaming is interrupted.
- Persistent public community chat history.
- Server-side message validation, rate limiting and text-only rendering through React.
- Server-side admin chat moderation endpoint and admin dashboard chat moderation tab.
- Realtime post/comment/reaction updates without manual refresh where the connection is available.
- Existing direct/group conversation database foundation remains intact and realtime delivery is scoped by conversation membership.
- Admin password configuration supports either `ADMIN_PASSWORD_HASH` or a server environment `ADMIN_PASSWORD`; when the latter is supplied, it is bcrypt-hashed at startup and only the hash is stored in SQLite.

## Secure admin configuration
Set these server environment variables in the deployment environment. Do **not** place secrets in frontend code or commit a real `.env` file.

```env
JWT_SECRET=replace-with-a-random-32-plus-character-secret
ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH=replace-with-bcrypt-hash
# Or, for first-time setup, provide ADMIN_PASSWORD in the server environment.
PORT=3000
```

The configured initial administrator password is the one specified in the Form 05 deployment instructions; it is intentionally not embedded in the frontend or README.

## Run

```bash
npm install
npm run dev
```

Production-style start:

```bash
npm run build
npm start
```

Node.js 20+ is required.

## Realtime behavior
The public chat uses an authenticated SSE stream at `/api/realtime`. Messages are still persisted in SQLite before they are broadcast. If a browser or deployment loses the stream, the client reconnects automatically and also performs a 10-second database refresh as a fallback.

## Verification status in this build environment
The source was structurally checked, but a full runtime build/E2E test could not be completed in the isolated environment because `npm install` could not reach `registry.npmjs.org` (DNS/network `EAI_AGAIN`). Therefore, no claim is made here that two external browser sessions have been successfully observed live in this environment.
