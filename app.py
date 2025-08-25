import os
import io
import json
import time
import uuid
import shutil
import subprocess
from pathlib import Path

from flask import (
    Flask, request, session, redirect, url_for, render_template, send_file,
    abort, Response, jsonify, stream_with_context
)
from werkzeug.utils import secure_filename

# ========= إعدادات =========
WORKSPACE = Path(os.getenv("WORKSPACE_DIR", "./workspace")).resolve()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "change-me")
SECRET_KEY = os.getenv("SECRET_KEY", os.urandom(24))
ALLOWED_EDIT_EXT = {"txt","md","json","py","js","ts","css","html","yaml","yml","ini","env","toml","sh"}

app = Flask(__name__)
app.secret_key = SECRET_KEY
WORKSPACE.mkdir(parents=True, exist_ok=True)

# عمليات شغّالة بالذاكرة
PROCESSES: dict[str, subprocess.Popen] = {}

# ========= أدوات مساعدة =========

def is_authed():
    return session.get("authed") is True

def require_auth():
    if not is_authed():
        return redirect(url_for("login"))

# منع الخروج عن الورك سبايس

def safe_path(p: str | Path) -> Path:
    target = (WORKSPACE / p).resolve() if not str(p).startswith(str(WORKSPACE)) else Path(p)
    if not str(target).startswith(str(WORKSPACE)):
        abort(400, "Bad path")
    return target

# ========= مصادقة =========
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        if request.form.get("password") == ADMIN_PASSWORD:
            session["authed"] = True
            return redirect(url_for("index"))
        return render_template("login.html", error="كلمة السر غلط")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ========= واجهة =========
@app.route("/")
def index():
    if not is_authed():
        return redirect(url_for("login"))
    return render_template("index.html", workspace=str(WORKSPACE))

# ========= ملفات ومجلدات =========
@app.get("/api/list")
def api_list():
    if not is_authed():
        abort(401)
    rel = request.args.get("path", "")
    base = safe_path(rel)
    if not base.exists():
        abort(404)
    if base.is_file():
        abort(400, "Path is a file")
    items = []
    for p in sorted(base.iterdir(), key=lambda x: (x.is_file(), x.name.lower())):
        items.append({
            "name": p.name,
            "is_dir": p.is_dir(),
            "size": (p.stat().st_size if p.is_file() else None),
            "mtime": int(p.stat().st_mtime*1000)
        })
    return jsonify({"cwd": str(base.relative_to(WORKSPACE)), "items": items})

@app.post("/api/mkdir")
def api_mkdir():
    if not is_authed():
        abort(401)
    data = request.json or {}
    rel = data.get("path", "")
    name = secure_filename(data.get("name", ""))
    if not name:
        abort(400, "Missing name")
    target = safe_path(Path(rel) / name)
    target.mkdir(parents=True, exist_ok=True)
    return {"ok": True}

@app.post("/api/upload")
def api_upload():
    if not is_authed():
        abort(401)
    rel = request.form.get("path", "")
    base = safe_path(rel)
    base.mkdir(parents=True, exist_ok=True)
    files = request.files.getlist("files")
    saved = []
    for f in files:
        fname = secure_filename(f.filename)
        if not fname:
            continue
        dest = base / fname
        f.save(dest)
        saved.append(fname)
    return {"ok": True, "saved": saved}

@app.post("/api/delete")
def api_delete():
    if not is_authed():
        abort(401)
    data = request.json or {}
    rel = data.get("path", "")
    base = safe_path(rel)
    if base.is_dir():
        shutil.rmtree(base)
    elif base.exists():
        base.unlink()
    return {"ok": True}

@app.get("/api/download")
def api_download():
    if not is_authed():
        abort(401)
    rel = request.args.get("path", "")
    p = safe_path(rel)
    if not p.is_file():
        abort(404)
    return send_file(p, as_attachment=True, download_name=p.name)

@app.get("/api/edit")
def api_edit_get():
    if not is_authed():
        abort(401)
    rel = request.args.get("path", "")
    p = safe_path(rel)
    if not p.exists() or not p.is_file():
        abort(404)
    if p.suffix.lstrip('.') not in ALLOWED_EDIT_EXT:
        abort(400, "Extension not allowed to edit")
    with open(p, 'r', encoding='utf-8', errors='ignore') as f:
        return {"content": f.read()}

@app.post("/api/edit")
def api_edit_post():
    if not is_authed():
        abort(401)
    data = request.json or {}
    rel = data.get("path")
    content = data.get("content")
    if rel is None or content is None:
        abort(400)
    p = safe_path(rel)
    if p.suffix.lstrip('.') not in ALLOWED_EDIT_EXT:
        abort(400, "Extension not allowed to edit")
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, 'w', encoding='utf-8') as f:
        f.write(content)
    return {"ok": True}

# ========= تشغيل أوامر + بث حي =========
@app.post("/api/run")
def api_run():
    if not is_authed():
        abort(401)
    data = request.json or {}
    cmd = data.get("cmd")
    cwd_rel = data.get("cwd", "")
    if not cmd:
        abort(400, "Missing cmd")
    cwd = safe_path(cwd_rel)
    if not cwd.exists():
        abort(400, "Bad cwd")
    pid = str(uuid.uuid4())
    # فتح العملية
    proc = subprocess.Popen(
        cmd, shell=True, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
    )
    PROCESSES[pid] = proc
    return {"pid": pid}

@app.get("/api/proc/<pid>/stream")
def api_stream(pid):
    if not is_authed():
        abort(401)
    proc = PROCESSES.get(pid)
    if not proc:
        abort(404)

    @stream_with_context
    def generate():
        yield "data: == Stream start ==\n\n"
        while True:
            line = proc.stdout.readline()
            if line:
                # أرسل كسطر SSE
                payload = json.dumps({"line": line.rstrip("\n")}, ensure_ascii=False)
                yield f"data: {payload}\n\n"
            if line == '' and proc.poll() is not None:
                break
        code = proc.returncode
        yield f"data: {{\"done\": true, \"code\": {code} }}\n\n"
        # نظف العملية
        try:
            del PROCESSES[pid]
        except KeyError:
            pass

    return Response(generate(), mimetype='text/event-stream')

@app.post("/api/proc/<pid>/kill")
def api_kill(pid):
    if not is_authed():
        abort(401)
    proc = PROCESSES.get(pid)
    if not proc:
        abort(404)
    proc.terminate()
    return {"ok": True}

# ========= قوالب مشاريع سريعة =========
@app.post("/api/scaffold")
def api_scaffold():
    if not is_authed():
        abort(401)
    data = request.json or {}
    kind = data.get("kind")  # "telegram-bot" | "static-site" | "flask-app"
    rel = data.get("path", "")
    base = safe_path(rel)
    base.mkdir(parents=True, exist_ok=True)

    if kind == "telegram-bot":
        (base / "requirements.txt").write_text("\n".join([
            "pyTelegramBotAPI==4.15.4",
            "requests==2.31.0"
        ]))
        (base / "bot.py").write_text(
            """import os, telebot, requests\nBOT_TOKEN=os.getenv('BOT_TOKEN'); OPENAI_API_KEY=os.getenv('OPENAI_API_KEY')\nbot=telebot.TeleBot(BOT_TOKEN)\n@bot.message_handler(func=lambda m: True)\ndef h(m):\n  txt=m.text or ''\n  payload={ 'model':'gpt-4o-mini','input':[{'role':'user','content':[{'type':'input_text','text':txt}]}] }\n  r=requests.post('https://api.openai.com/v1/responses',headers={'Authorization':f'Bearer {OPENAI_API_KEY}','Content-Type':'application/json'},json=payload)\n  data=r.json(); out=(data.get('output_text') or data.get('output',[{}])[0].get('content',[{}])[0].get('text') or str(data))\n  bot.reply_to(m,out)\nprint('Bot running'); bot.infinity_polling()\n""")
        msg = "تم إنشاء قالب بوت تيليجرام."

    elif kind == "static-site":
        (base / "index.html").write_text("""<!doctype html><meta charset='utf-8'><title>Static Site</title><h1>Hello VPS</h1>""")
        msg = "تم إنشاء موقع ساكن بسيط."

    elif kind == "flask-app":
        (base / "requirements.txt").write_text("Flask==3.0.2\n")
        (base / "main.py").write_text("""from flask import Flask; app=Flask(__name__)\n@app.get('/')\ndef hi(): return 'Hello from Flask app'\nif __name__=='__main__': app.run(host='0.0.0.0',port=8000)\n""")
        msg = "تم إنشاء قالب Flask."
    else:
        abort(400, "Unknown kind")

    return {"ok": True, "message": msg}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
