from dotenv import load_dotenv
load_dotenv()

import os
import sqlite3
import asyncio
import smtplib
from email.message import EmailMessage
from datetime import date, datetime, timedelta
from typing import List

from fastapi import FastAPI, HTTPException, Response, Request, Depends
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from passlib.context import CryptContext
from jose import jwt, JWTError

app = FastAPI(title="Letters App (Auth)")
DB_PATH = "letters.db"

# --- Email helper (SMTP) ---
def send_email(to_email: str, subject: str, body: str):
    host = os.getenv("SMTP_HOST")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER")
    password = os.getenv("SMTP_PASS")
    mail_from = os.getenv("MAIL_FROM", user)

    if not all([host, user, password, mail_from]):
        raise RuntimeError("Missing SMTP env vars. Check your .env file.")

    msg = EmailMessage()
    msg["From"] = mail_from
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    with smtplib.SMTP(host, port) as server:
        server.starttls()
        server.login(user, password)
        server.send_message(msg)

# --- Auth config ---
JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET is missing. Add it to your .env file.")

JWT_ALG = "HS256"
SESSION_COOKIE = "session"
SESSION_DAYS = 7

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


@app.on_event("startup")
async def startup():
    init_db()
    asyncio.create_task(delivery_worker())




# --- Auth config ---
JWT_SECRET = os.getenv("JWT_SECRET")

if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET is missing. Add it to your .env file.")
JWT_ALG = "HS256"
SESSION_COOKIE = "session"
SESSION_DAYS = 7

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn



def mark_sent(letter_id):
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "UPDATE letters SET sent_at = datetime('now') WHERE id = ?",
        (letter_id,)
    )
    conn.commit()
    conn.close()

    
    

def init_db():
    conn = db()
    cur = conn.cursor()

    # Users table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
    """)

    # Letters table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS letters (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        recipient TEXT NOT NULL,
        subject TEXT NOT NULL,
        body TEXT NOT NULL,
        deliver_on TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        sent_at TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)

    # Migration (add sent_at if missing)
    cols = [r[1] for r in cur.execute("PRAGMA table_info(letters)").fetchall()]
    if "sent_at" not in cols:
        cur.execute("ALTER TABLE letters ADD COLUMN sent_at TEXT")

    conn.commit()
    conn.close()







# --- Models ---
class RegisterIn(BaseModel):
    email: str = Field(min_length=5, max_length=255)
    password: str = Field(min_length=6, max_length=200)


class LoginIn(BaseModel):
    email: str = Field(min_length=5, max_length=255)
    password: str = Field(min_length=6, max_length=200)


class UserOut(BaseModel):
    id: int
    email: str
    created_at: str


class LetterCreate(BaseModel):
    recipient: str = Field(min_length=1, max_length=120)
    subject: str = Field(min_length=1, max_length=160)
    body: str = Field(min_length=1, max_length=5000)
    deliver_on: str = Field(min_length=4, max_length=32)


class LetterOut(BaseModel):
    id: int
    user_id: int
    recipient: str
    subject: str
    body: str
    deliver_on: str
    created_at: str
    sent_at: str | None = None


# --- Auth helpers ---
def hash_password(pw: str) -> str:
    return pwd_context.hash(pw)


def verify_password(pw: str, pw_hash: str) -> bool:
    return pwd_context.verify(pw, pw_hash)


def create_token(user_id: int) -> str:
    exp = datetime.utcnow() + timedelta(days=SESSION_DAYS)
    payload = {"sub": str(user_id), "exp": exp}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def get_user_by_email(email: str):
    conn = db()
    row = conn.execute("SELECT * FROM users WHERE email = ?", (email.lower().strip(),)).fetchone()
    conn.close()
    return row


def get_user_by_id(user_id: int):
    conn = db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return row


def current_user(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(status_code=401, detail="Not logged in")

    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id = int(data["sub"])
    except (JWTError, KeyError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid session")

    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user


# --- Page ---
@app.get("/", response_class=HTMLResponse)
def home():
    return """
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Letters App</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 16px; }
    h1 { margin-bottom: 8px; }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    input, textarea { width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 8px; }
    textarea { min-height: 140px; resize: vertical; }
    button { padding: 10px 14px; border: 0; border-radius: 10px; cursor: pointer; }
    button.primary { background: #111; color: #fff; }
    button.secondary { background: #eee; }
    .card { border: 1px solid #eee; border-radius: 12px; padding: 14px; margin-top: 12px; }
    .meta { color: #666; font-size: 12px; margin-top: 6px; }
    .error { color: #b00020; margin-top: 10px; }
    .success { color: #0a7a0a; margin-top: 10px; }
    hr { border: none; border-top: 1px solid #eee; margin: 22px 0; }
    .topbar { display:flex; justify-content:space-between; align-items:center; gap:12px; }
    .hidden { display:none; }
    .small { font-size: 13px; color:#666; }
  </style>
</head>
<body>
  <div class="topbar">
    <div>
      <h1>Letters</h1>
      <div class="small" id="whoami"></div>
    </div>
    <div style="display:flex; gap:8px;">
      <button class="secondary" onclick="logout()">Logout</button>
    </div>
  </div>

  <div id="authBox" class="card">
    <h2>Login</h2>
    <div class="row">
      <div>
        <label>Email</label>
        <input id="login_email" placeholder="you@email.com" />
      </div>
      <div>
        <label>Password</label>
        <input id="login_password" type="password" placeholder="******" />
      </div>
    </div>
    <div style="margin-top:12px; display:flex; gap:10px; align-items:center;">
      <button class="primary" onclick="login()">Login</button>
      <button onclick="registerUser()">Register</button>
      <span id="authStatus"></span>
    </div>
    <div class="small" style="margin-top:8px;">
      Register creates an account and logs you in.
    </div>
  </div>

  <div id="appBox" class="hidden">
    <p>Create a letter and list them below.</p>

    <div class="row">
      <div>
        <label>Recipient</label>
        <input id="recipient" placeholder="e.g., John" />
      </div>
      <div>
        <label>Deliver on (YYYY-MM-DD)</label>
        <input id="deliver_on" placeholder="e.g., 2026-12-30" />
      </div>
    </div>

    <div style="margin-top:12px;">
      <label>Subject</label>
      <input id="subject" placeholder="e.g., Open this when..." />
    </div>

    <div style="margin-top:12px;">
      <label>Body</label>
      <textarea id="body" placeholder="Write your letter..."></textarea>
    </div>

    <div style="margin-top:12px; display:flex; gap:10px; align-items:center;">
      <button class="primary" onclick="createLetter()">Create Letter</button>
      <button onclick="loadLetters()">Refresh List</button>
      <span id="status"></span>
    </div>

    <hr />

    <h2>Saved Letters</h2>
    <div id="letters"></div>
  </div>

<script>
  const statusEl = document.getElementById("status");
  const authStatusEl = document.getElementById("authStatus");
  const authBox = document.getElementById("authBox");
  const appBox = document.getElementById("appBox");
  const whoamiEl = document.getElementById("whoami");

  function setStatus(msg, type="") {
    statusEl.className = type;
    statusEl.textContent = msg;
    if (msg) setTimeout(() => { statusEl.textContent = ""; statusEl.className=""; }, 2500);
  }

  function setAuthStatus(msg, type="") {
    authStatusEl.className = type;
    authStatusEl.textContent = msg;
    if (msg) setTimeout(() => { authStatusEl.textContent = ""; authStatusEl.className=""; }, 2500);
  }

  function escapeHtml(str) {
    return str.replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;");
  }

  async function refreshAuthState() {
    const res = await fetch("/api/me");
    if (res.ok) {
      const me = await res.json();
      whoamiEl.textContent = "Logged in as: " + me.email;
      authBox.classList.add("hidden");
      appBox.classList.remove("hidden");
      await loadLetters();
    } else {
      whoamiEl.textContent = "";
      authBox.classList.remove("hidden");
      appBox.classList.add("hidden");
    }
  }

  async function registerUser() {
    const email = document.getElementById("login_email").value.trim();
    const password = document.getElementById("login_password").value.trim();

    const res = await fetch("/api/register", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ email, password })
    });

    if (!res.ok) {
      const txt = await res.text();
      setAuthStatus("Register failed: " + txt, "error");
      return;
    }

    setAuthStatus("Registered + logged in!", "success");
    await refreshAuthState();
  }

  async function login() {
    const email = document.getElementById("login_email").value.trim();
    const password = document.getElementById("login_password").value.trim();

    const res = await fetch("/api/login", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ email, password })
    });

    if (!res.ok) {
      const txt = await res.text();
      setAuthStatus("Login failed: " + txt, "error");
      return;
    }

    setAuthStatus("Logged in!", "success");
    await refreshAuthState();
  }

  async function logout() {
    await fetch("/api/logout", { method: "POST" });
    await refreshAuthState();
  }

  async function createLetter() {
    const recipient = document.getElementById("recipient").value.trim();
    const subject = document.getElementById("subject").value.trim();
    const body = document.getElementById("body").value.trim();
    const deliver_on = document.getElementById("deliver_on").value.trim();

    const res = await fetch("/api/letters", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ recipient, subject, body, deliver_on })
    });

    if (!res.ok) {
      const txt = await res.text();
      setStatus("Error: " + txt, "error");
      return;
    }

    document.getElementById("recipient").value = "";
    document.getElementById("subject").value = "";
    document.getElementById("body").value = "";
    document.getElementById("deliver_on").value = "";

    setStatus("Saved!", "success");
    await loadLetters();
  }

  async function loadLetters() {
    const box = document.getElementById("letters");
    box.innerHTML = "Loading...";

    const res = await fetch("/api/letters");
    if (!res.ok) {
      box.innerHTML = "<p>Please login.</p>";
      return;
    }

    const data = await res.json();

    if (!Array.isArray(data) || data.length === 0) {
      box.innerHTML = "<p>No letters yet.</p>";
      return;
    }

       box.innerHTML = data.map(l => `
      <div class="card">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <strong>${escapeHtml(l.subject)}</strong>
          <span style="
            padding:4px 8px;
            border-radius:6px;
            font-size:12px;
            background:${l.sent_at ? "#0a7a0a" : "#444"};
            color:white;
          ">
            ${l.sent_at ? "SENT" : "PENDING"}
          </span>
        </div>

        <div>To: ${escapeHtml(l.recipient)} · Deliver: ${escapeHtml(l.deliver_on)}</div>

        <div style="margin-top:10px; white-space:pre-wrap;">
          ${escapeHtml(l.body)}
        </div>

        <div class="meta">
          Created: ${escapeHtml(l.created_at)}
          ${l.sent_at ? " · Sent: " + escapeHtml(l.sent_at) : ""}
        </div>
      </div>
    `).join("");
  }

  refreshAuthState();
</script>
</body>
</html>
"""



# --- Auth API ---
@app.post("/api/register", response_model=UserOut)
def register(payload: RegisterIn, response: Response):
    email = payload.email.lower().strip()

    if get_user_by_email(email):
        raise HTTPException(status_code=400, detail="Email already registered")

    conn = db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO users (email, password_hash) VALUES (?, ?)",
        (email, hash_password(payload.password)),
    )
    conn.commit()
    user_id = cur.lastrowid
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()

    token = create_token(user_id)
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=SESSION_DAYS * 24 * 60 * 60,
    )

    return dict(row)


@app.post("/api/login")
def login(payload: LoginIn, response: Response):
    email = payload.email.lower().strip()
    user = get_user_by_email(email)
    if not user or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_token(user["id"])
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=SESSION_DAYS * 24 * 60 * 60,
    )
    return {"ok": True}


@app.post("/api/logout")
def logout(response: Response):
    response.delete_cookie(SESSION_COOKIE)
    return {"ok": True}


@app.get("/api/me", response_model=UserOut)
def me(user=Depends(current_user)):
    return {"id": user["id"], "email": user["email"], "created_at": user["created_at"]}


# --- Letters API (auth required) ---
@app.post("/api/letters", response_model=LetterOut)
def create_letter(payload: LetterCreate, user=Depends(current_user)):
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO letters (user_id, recipient, subject, body, deliver_on)
        VALUES (?, ?, ?, ?, ?)
        """,
        (user["id"], payload.recipient, payload.subject, payload.body, payload.deliver_on),
    )
    conn.commit()
    letter_id = cur.lastrowid
    row = conn.execute("SELECT * FROM letters WHERE id = ?", (letter_id,)).fetchone()
    conn.close()
    return dict(row)


@app.get("/api/letters", response_model=List[LetterOut])
def list_letters(user=Depends(current_user)):
    conn = db()
    rows = conn.execute(
        "SELECT * FROM letters WHERE user_id = ? ORDER BY id DESC",
        (user["id"],),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_pending_letters():
    conn = db()
    today = date.today().isoformat()
    rows = conn.execute(
        """
        SELECT letters.*, users.email AS user_email
        FROM letters
        JOIN users ON users.id = letters.user_id
        WHERE letters.sent_at IS NULL
          AND letters.deliver_on <= ?
        ORDER BY letters.id ASC
        """,
        (today,),
    ).fetchall()
    conn.close()
    return rows


def mark_letter_sent(letter_id: int):
    conn = db()
    conn.execute(
        "UPDATE letters SET sent_at = ? WHERE id = ?",
        (datetime.utcnow().isoformat(), letter_id),
    )
    conn.commit()
    conn.close()


async def delivery_worker():
    while True:
        try:
            pending = get_pending_letters()

            for r in pending:
                try:
                    to_email = r["user_email"]
                    subject = f"Your scheduled letter: {r['subject']}"
                    body = (
                        f"To: {r['recipient']}\n"
                        f"Deliver on: {r['deliver_on']}\n\n"
                        f"{r['body']}\n"
                    )

                    # Send real email (non-blocking)
                    await asyncio.to_thread(send_email, to_email, subject, body)

                    # Only mark as sent AFTER success
                    mark_letter_sent(r["id"])

                    print(f"✅ Email sent to {to_email}")

                except Exception as e:
                    print(f"❌ Email failed: {repr(e)}")

        except Exception as e:
            print("Worker loop error:", repr(e))

        await asyncio.sleep(10)



