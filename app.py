import os, secrets, hmac, sqlite3
from flask import Flask, request, jsonify, send_file, session
from functools import wraps
from contextlib import contextmanager
import psycopg
app=Flask(__name__)
app.secret_key=os.environ.get("SESSION_SECRET") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SECURE=True,SESSION_COOKIE_SAMESITE="Strict",MAX_CONTENT_LENGTH=1000000)
@contextmanager
def db():
    url=os.environ.get("DATABASE_URL")
    conn=psycopg.connect(url) if url else sqlite3.connect("/tmp/nosso.db")
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS expenses (id TEXT PRIMARY KEY, payload TEXT NOT NULL)")
        yield conn, "%s" if url else "?"
        conn.commit()
    finally: conn.close()
def auth(fn):
    @wraps(fn)
    def wrapped(*a,**kw):
        if not session.get("user"): return jsonify(error="Login necessário"),401
        if request.method not in ("GET","HEAD") and request.headers.get("X-Nosso")!="1": return jsonify(error="Requisição inválida"),403
        return fn(*a,**kw)
    return wrapped
@app.get("/")
def index(): return send_file("index.html")
@app.get("/health")
def health(): return jsonify(ok=True)
@app.post("/api/login")
def login():
    body=request.get_json() or {}
    user=body.get("user")
    password=body.get("password")
    expected=os.environ.get("PASSWORD_"+str(user).upper()) if user in ("Jhonatan","Ari") else None
    if not expected or not isinstance(password,str) or not hmac.compare_digest(expected,password): return jsonify(error="Credenciais inválidas"),401
    session.clear()
    session["user"]=user
    return jsonify(ok=True)
@app.post("/api/logout")
@auth
def logout():
    session.clear()
    return jsonify(ok=True)
@app.get("/api/expenses")
@auth
def expenses():
    import json
    with db() as (c,p): return jsonify([json.loads(r[0]) for r in c.execute("SELECT payload FROM expenses").fetchall()])
@app.put("/api/expenses")
@auth
def save():
    import json, datetime
    e=request.get_json()
    try:
        assert isinstance(e,dict)
        assert isinstance(e["id"],str) and 0<len(e["id"])<=100
        assert type(e["cents"]) is int and 0<e["cents"]<=100000000000
        assert e["person"] in ("Jhonatan","Ari","Casa")
        datetime.date.fromisoformat(e["date"])
        for k in ("description","category","type","platform"):
            assert isinstance(e[k],str) and 0<len(e[k].strip())<=200
    except (AssertionError,KeyError,TypeError,ValueError): return jsonify(error="Dados inválidos"),400
    with db() as (c,p): c.execute(f"INSERT INTO expenses (id,payload) VALUES ({p},{p}) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",(e["id"],json.dumps(e)))
    return jsonify(ok=True)
@app.delete("/api/expenses/<id>")
@auth
def delete(id):
    with db() as (c,p): c.execute(f"DELETE FROM expenses WHERE id={p}",(id,))
    return jsonify(ok=True)
