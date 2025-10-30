# AKITAMIA Airdrop - Backend Server

Backend API server for AKITAMIA airdrop claim system.

## Architecture

- **Frontend**: Hosted at https://akitamia.dog (website.html + airdrop.html)
- **Backend**: This repo → Deploy to Render
- **Database**: PostgreSQL on Render

## Environment Variables Required

Add these in Render dashboard:

```bash
# Database (Render PostgreSQL will provide these)
DB_USER=<from_render>
DB_HOST=<from_render>
DB_NAME=akitamia_airdrop
DB_PASSWORD=<from_render>
DB_PORT=5432

# Server
PORT=3001

# Rate Limiting
RATE_LIMIT_WINDOW_MS=3600000
RATE_LIMIT_MAX_REQUESTS=10000

# Authentication
AIRDROP_USERNAME=<your_secure_username>
AIRDROP_PASSWORD=<your_secure_password>

# CORS (Allow your frontend domain)
ALLOWED_ORIGINS=https://akitamia.dog,https://x.com,https://bitbit.bot
```

## Deployment Steps

1. Connect this repo to Render
2. Create PostgreSQL database on Render
3. Add all environment variables above
4. Deploy!

## API Endpoints

- `POST /api/auth/login` - Authenticate access
- `POST /api/save-claim` - Submit signed claim
- `GET /api/check-wallet/:address` - Check wallet status
- `GET /api/check-spark/:address` - Check Spark address
- `GET /api/claims/spark/:address` - Query claim by Spark address
- `GET /api/v1/public/claim/:sparkAddress` - Public API endpoint

## Security Features

- ✅ Input sanitization (alphanumeric-only validation)
- ✅ Server-side claim verification via Hiro API
- ✅ Rate limiting (10,000 requests/hour per IP)
- ✅ CORS restricted to whitelisted domains
- ✅ SQL injection protection (parameterized queries)
- ✅ Request body size limit (1mb)
- ✅ Authentication required for airdrop page access

## Tech Stack

- Node.js + Express
- PostgreSQL
- Hiro API (Bitcoin blockchain verification)
