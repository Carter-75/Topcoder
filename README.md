# Topcoder Guardrails Backend

## Overview
This project is a secure, modular backend for code analysis, policy enforcement, and audit logging. It uses FastAPI and includes endpoints for code analysis, health checks, and a dashboard for audit logs.

## Features
- REST API for code analysis (`/analyze`)
- Health check endpoint (`/health`)
- Audit dashboard (`/dashboard`)
- Modular rulepacks for different sectors
- Security, coding standards, license/IP, and AI review checks

## Requirements
- Python 3.9+
- See `backend/requirements.txt` for all dependencies

## Installation
1. Clone the repository.
2. Navigate to the backend directory:
   ```sh
   cd Topcoder/backend
   ```
3. (Recommended) Create a virtual environment:
   ```sh
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```
4. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```

## Configuration
- Copy `.env.example` to `.env` and set your API key:
  ```sh
  cp .env.example .env
  # Edit .env and set API_KEY=your-key-here
  ```
- The API key is required for some AI review features.

## Running the Server
From the `Topcoder/backend` directory:
```sh
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

## API Endpoints
- `GET /health` — Health check
- `POST /analyze` — Analyze code (JSON: `{ "code": "..." }`)
- `GET /dashboard` — View audit dashboard
- `GET /docs` — Interactive API docs (Swagger UI)

## Testing
Run all backend tests:
```sh
pytest
```

## Notes
- All dependencies are listed in `requirements.txt`.
- The dashboard reads from `audit_log.jsonl`.
- For production, set environment variables securely and use HTTPS.

## Changelog
- 2026-01-26: Full test and endpoint verification, requirements and documentation updated.
