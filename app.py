import os, secrets, hmac, json
from datetime import datetime
from zoneinfo import ZoneInfo
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
    if not url:
        raise psycopg.OperationalError("Database not configured")
    with psycopg.connect(url, connect_timeout=10, sslmode="require") as conn:
        yield conn, "%s"
@app.errorhandler(psycopg.Error)
def database_error(error):
    app.logger.warning("Database operation failed: %s", type(error).__name__)
    return jsonify(error="Banco temporariamente indisponível"),503
def auth(fn):
    @wraps(fn)
    def wrapped(*a,**kw):
        if not session.get("user"): return jsonify(error="Login necessário"),401
        if request.method not in ("GET","HEAD") and request.headers.get("X-Nosso")!="1": return jsonify(error="Requisição inválida"),403
        return fn(*a,**kw)
    return wrapped
@app.after_request
def prevent_stale_financial_data(response):
    if request.path == "/" or request.path.startswith("/api/") or request.path == "/health":
        response.headers["Cache-Control"] = "no-store, private, max-age=0"
    return response

@app.get("/")
def index(): return send_file("index.html", conditional=False, max_age=0)

@app.get("/api/snapshot")
@auth
def snapshot():
    with db() as (c,p):
        c.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        expenses = [json.loads(r[0]) for r in c.execute("SELECT payload FROM public.expenses ORDER BY id").fetchall()]
        incomes = [json.loads(r[0]) for r in c.execute("SELECT payload FROM public.incomes ORDER BY id").fetchall()]
    return jsonify(expenses=expenses, incomes=incomes)

@app.get("/health")
def health():
    if not os.environ.get("DATABASE_URL"): return jsonify(ok=False,database="not_configured"),503
    try:
        with db() as (c,p):
            c.execute("SELECT 1 FROM public.expenses LIMIT 1").fetchall()
            c.execute("SELECT 1 FROM public.incomes LIMIT 1").fetchall()
        return jsonify(ok=True,database="postgresql")
    except Exception:
        return jsonify(ok=False,database="unavailable"),503
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
    with db() as (c,p): return jsonify([json.loads(r[0]) for r in c.execute("SELECT payload FROM public.expenses").fetchall()])
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
    status = e.get("status", "Pendente")
    if status not in ("Pendente", "Pago"):
        return jsonify(error="Situação de pagamento inválida"),400
    with db() as (c,p):
        old = c.execute("SELECT payload FROM public.expenses WHERE id=%s FOR UPDATE", (e["id"],)).fetchone()
        previous = json.loads(old[0]) if old else {}
        e["status"] = status
        e["paid_at"] = (previous.get("paid_at") or payment_day()) if status == "Pago" else None
        c.execute("INSERT INTO public.expenses (id,payload) VALUES (%s,%s) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",(e["id"],json.dumps(e)))
    return jsonify(ok=True)

def payment_day():
    return datetime.now(ZoneInfo("America/Sao_Paulo")).date().isoformat()

def bill_key(e):
    return (e["person"], e["platform"].strip().lower(), e["type"], e["date"][:7])

@app.post("/api/expenses/payment")
@auth
def change_payment():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify(error="Dados inválidos"),400
    ids, status = body.get("ids"), body.get("status")
    if not isinstance(ids,list) or not 1 <= len(ids) <= 1000 or not all(isinstance(i,str) and 0<len(i)<=100 for i in ids) or status not in ("Pago","Pendente"):
        return jsonify(error="Dados inválidos"),400
    ids = sorted(set(ids))
    with db() as (c,p):
        rows = c.execute("SELECT id,payload FROM public.expenses WHERE id=ANY(%s) ORDER BY id FOR UPDATE",(ids,)).fetchall()
        if len(rows) != len(ids):
            return jsonify(error="Algum lançamento não existe mais. Atualize os dados."),409
        records = [(i,json.loads(payload)) for i,payload in rows]
        if len({bill_key(e) for _,e in records}) != 1:
            return jsonify(error="Selecione despesas da mesma conta e mês"),400
        for i,e in records:
            e["status"] = status
            e["paid_at"] = (e.get("paid_at") or payment_day()) if status == "Pago" else None
            c.execute("UPDATE public.expenses SET payload=%s WHERE id=%s",(json.dumps(e),i))
    return jsonify(ok=True,count=len(ids))

@app.delete("/api/expenses/<id>")
@auth
def delete(id):
    with db() as (c,p): c.execute(f"DELETE FROM public.expenses WHERE id={p}",(id,))
    return jsonify(ok=True)

@app.get("/api/incomes")
@auth
def incomes():
    import json
    with db() as (c,p): return jsonify([json.loads(r[0]) for r in c.execute("SELECT payload FROM public.incomes").fetchall()])
@app.put("/api/incomes")
@auth
def save_income():
    import json, datetime
    e=request.get_json()
    try:
        assert isinstance(e,dict)
        assert isinstance(e["id"],str) and 0<len(e["id"])<=100
        assert type(e["cents"]) is int and 0<e["cents"]<=100000000000
        assert e["person"] in ("Jhonatan","Ari","Casa")
        assert e["status"] in ("Prevista","Recebida")
        assert isinstance(e["description"],str) and 0<len(e["description"].strip())<=200
        datetime.date.fromisoformat(e["date"])
    except (AssertionError,KeyError,TypeError,ValueError): return jsonify(error="Dados inválidos"),400
    with db() as (c,p): c.execute(f"INSERT INTO public.incomes (id,payload) VALUES ({p},{p}) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",(e["id"],json.dumps(e)))
    return jsonify(ok=True)
@app.delete("/api/incomes/<id>")
@auth
def delete_income(id):
    with db() as (c,p): c.execute(f"DELETE FROM public.incomes WHERE id={p}",(id,))
    return jsonify(ok=True)
