# echoletter-backend-point0
# EchoLetter Backend (FastAPI)

A scheduled letter delivery backend built with **FastAPI**, **JWT cookie auth**, **SQLite**, and an **async delivery worker** that emails letters via SMTP when their delivery date arrives.

## Features
- Register / Login (JWT stored in cookie)
- Create and list letters
- Letters show status: **PENDING** / **SENT**
- Background worker checks for due letters and sends email via SMTP

## Tech Stack
- FastAPI
- SQLite
- JWT (python-jose)
- passlib/bcrypt
- SMTP email (Gmail app password)

## Setup

### 1) Create virtual env + install
```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
pip install -r requirements.txt
