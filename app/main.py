"""经营方法论中枢：鉴权、多用户知识库、乐观并发、历史版本。
支持 SQLite（本地）或 PostgreSQL（生产）。
"""
from __future__ import annotations
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response, Depends
from fastapi.responses import FileResponse, RedirectResponse, JSONResponse
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / 'static'
DB_URL = os.getenv('DATABASE_URL', '').strip()
SQLITE_PATH = Path(os.getenv('SQLITE_PATH', '/data/knowledge.db'))
IS_POSTGRES = DB_URL.startswith(('postgresql://', 'postgres://'))
COOKIE_SECURE = os.getenv('COOKIE_SECURE', 'true').lower() not in ('0', 'false', 'no')
SESSION_DAYS = 7
MAX_JSON_BYTES = 2_000_000
AUTH_COOKIE = 'method_session'
LOGIN_FAILURES: dict[str, list[float]] = {}

app = FastAPI(title='经营方法论中枢 API', docs_url=None, redoc_url=None, openapi_url=None)


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def time_plus_days(days: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat(timespec='seconds')


def password_hash(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 390_000)
    return f'pbkdf2_sha256$390000${salt}${dk.hex()}'


def verify_password(password: str, stored: str) -> bool:
    try:
        alg, rounds, salt, expected = stored.split('$')
        if alg != 'pbkdf2_sha256': return False
        actual = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), int(rounds))
        return hmac.compare_digest(actual.hex(), expected)
    except (ValueError, TypeError):
        return False


@contextmanager
def connection():
    if IS_POSTGRES:
        import psycopg
        from psycopg.rows import dict_row
        conn = psycopg.connect(DB_URL, row_factory=dict_row)
    else:
        SQLITE_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(SQLITE_PATH), timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA busy_timeout=30000')
        conn.execute('PRAGMA foreign_keys=ON')
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def sql(conn, statement: str, *params):
    if IS_POSTGRES:
        statement = statement.replace('?', '%s')
    return conn.execute(statement, params)


def one(conn, statement: str, *params) -> dict | None:
    r = sql(conn, statement, *params).fetchone()
    return dict(r) if r else None


def rows(conn, statement: str, *params) -> list[dict]:
    return [dict(x) for x in sql(conn, statement, *params).fetchall()]


def initialize():
    with connection() as conn:
        for ddl in (
            'CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL)',
            'CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, csrf_token TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL)',
            'CREATE TABLE IF NOT EXISTS knowledge (id INTEGER PRIMARY KEY, version INTEGER NOT NULL, content TEXT NOT NULL, updated_at TEXT NOT NULL, updated_by TEXT NOT NULL)',
            'CREATE TABLE IF NOT EXISTS revisions (version INTEGER PRIMARY KEY, content TEXT NOT NULL, author TEXT NOT NULL, created_at TEXT NOT NULL, summary TEXT NOT NULL)',
        ):
            sql(conn, ddl)
        if one(conn, 'SELECT id FROM knowledge WHERE id=1') is None:
            seed = json.loads((ROOT / 'seed_chapters.json').read_text('utf-8'))
            content = json.dumps(seed, ensure_ascii=False, separators=(',', ':'))
            sql(conn, 'INSERT INTO knowledge (id,version,content,updated_at,updated_by) VALUES (1,1,?,?,?)', content, now(), '系统初始化')
            sql(conn, 'INSERT INTO revisions (version,content,author,created_at,summary) VALUES (1,?,?,?,?)', content, '系统初始化', now(), '原始方法论数据导入')
        count = one(conn, 'SELECT COUNT(*) AS n FROM users')['n']
        if not count:
            user = os.getenv('ADMIN_USERNAME', 'admin').strip()
            password = os.getenv('ADMIN_PASSWORD', '')
            if not re.fullmatch(r'[A-Za-z0-9_.@-]{3,64}', user):
                raise RuntimeError('ADMIN_USERNAME 无效，长度3-64，仅限英数和 ._@-')
            if len(password) < 12:
                raise RuntimeError('首次运行必须配置 ADMIN_PASSWORD（至少12位），不要使用示例密码')
            sql(conn, 'INSERT INTO users VALUES (?,?,?,?,?)', user, password_hash(password), 'admin', 1, now())


@app.on_event('startup')
def startup():
    initialize()


class SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, req, call_next):
        response = await call_next(req)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Cache-Control'] = 'no-store'
        if COOKIE_SECURE:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response


app.add_middleware(SecurityHeaders)


def session_user(req: Request) -> dict | None:
    token = req.cookies.get(AUTH_COOKIE)
    if not token: return None
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with connection() as conn:
        data = one(conn, '''SELECT u.username,u.role,u.active,s.csrf_token,s.expires_at FROM sessions s
                        JOIN users u ON u.username=s.username WHERE s.token_hash=?''', token_hash)
    if not data or not data['active'] or data['expires_at'] <= now():
        return None
    return data


def require_user(req: Request) -> dict:
    user = session_user(req)
    if not user:
        raise HTTPException(401, '请先登录')
    return user


def require_edit(req: Request) -> dict:
    user = require_user(req)
    if user['role'] not in ('admin', 'editor'):
        raise HTTPException(403, '没有编辑权限')
    check_csrf(req, user)
    return user


def require_admin(req: Request) -> dict:
    user = require_user(req)
    if user['role'] != 'admin':
        raise HTTPException(403, '仅管理员可以操作')
    check_csrf(req, user)
    return user


def check_csrf(req: Request, user: dict):
    provided = req.headers.get('x-csrf-token', '')
    if not provided or not hmac.compare_digest(provided, user['csrf_token']):
        raise HTTPException(403, 'CSRF令牌无效，请刷新页面')
    origin = req.headers.get('origin')
    if origin:
        # 检查 Origin 与实际请求主机（反向代理需要保留转发 Host）一致
        from urllib.parse import urlsplit
        parsed = urlsplit(origin)
        if parsed.netloc != req.headers.get('host', ''):
            raise HTTPException(403, '跨域写入被拒绝')


def validate_chapters(chapters: Any) -> list:
    if not isinstance(chapters, list) or not (1 <= len(chapters) <= 100):
        raise HTTPException(422, '一级章节应为1-100个')
    keys = set()
    for c in chapters:
        if not isinstance(c, dict) or not isinstance(c.get('stages'), list):
            raise HTTPException(422, '章节格式不合法')
        if not isinstance(c.get('name'), str) or not c['name'].strip():
            raise HTTPException(422, '章节名称不能为空')
        if len(c['stages']) > 100:
            raise HTTPException(422, '单章最多100个小章节')
        cid = c.get('id')
        if not isinstance(cid, str) or cid in keys or not re.fullmatch(r'[\w-]{1,100}', cid):
            raise HTTPException(422, '章节ID不合法或重复')
        keys.add(cid)
        for s in c['stages']:
            if not isinstance(s, dict) or not isinstance(s.get('methods'), list):
                raise HTTPException(422, '小章节格式不合法')
            if len(s['methods']) > 1000: raise HTTPException(422, '方法条目过多')
            for m in s['methods']:
                if not isinstance(m, dict) or not isinstance(m.get('actions', []), list) or not isinstance(m.get('tags', []), list):
                    raise HTTPException(422, '方法卡片格式不合法')
    encoded = json.dumps(chapters, ensure_ascii=False, separators=(',', ':'))
    if len(encoded.encode('utf-8')) > MAX_JSON_BYTES:
        raise HTTPException(413, '知识库超过2MB限制')
    return chapters


class Credentials(BaseModel):
    username: str
    password: str


class KnowledgeUpdate(BaseModel):
    version: int = Field(ge=1)
    chapters: list
    summary: str = Field(default='更新方法论内容', max_length=200)


class UserCreate(BaseModel):
    username: str
    password: str
    role: str = 'viewer'


class UserPatch(BaseModel):
    role: str | None = None
    active: bool | None = None
    password: str | None = None


@app.get('/api/health')
def health():
    try:
        with connection() as conn:
            ok = one(conn, 'SELECT version FROM knowledge WHERE id=1')
        return {'ok': bool(ok)}
    except Exception:
        return JSONResponse({'ok': False}, status_code=503)


@app.post('/api/login')
def login(req: Request, data: Credentials, response: Response):
    key = f'{req.client.host if req.client else "unknown"}:{data.username}'
    t = time.monotonic()
    attempts = [x for x in LOGIN_FAILURES.get(key, []) if t - x < 600]
    if len(attempts) >= 8:
        raise HTTPException(429, '尝试次数过多，请稍后重试')
    with connection() as conn:
        user = one(conn, 'SELECT * FROM users WHERE username=?', data.username)
        valid = bool(user and user['active'] and verify_password(data.password, user['password_hash']))
        if not valid:
            # 为不存在的账户模拟一次PBKDF2运算，减小账户枚举风险
            if not user: password_hash(data.password, '0'*32)
            attempts.append(t)
            LOGIN_FAILURES[key] = attempts
            raise HTTPException(401, '用户名或密码错误')
        LOGIN_FAILURES.pop(key, None)
        token = secrets.token_urlsafe(48)
        csrf = secrets.token_urlsafe(32)
        sql(conn, 'INSERT INTO sessions (token_hash,username,csrf_token,expires_at,created_at) VALUES (?,?,?,?,?)', hashlib.sha256(token.encode()).hexdigest(), user['username'], csrf, time_plus_days(SESSION_DAYS), now())
    response.set_cookie(AUTH_COOKIE, token, httponly=True, secure=COOKIE_SECURE, samesite='lax', max_age=SESSION_DAYS*86400, path='/')
    return {'ok': True, 'role': user['role'], 'username': user['username']}


@app.post('/api/logout')
def logout(req: Request, response: Response, user: dict = Depends(require_user)):
    check_csrf(req, user)
    token = req.cookies.get(AUTH_COOKIE)
    with connection() as conn:
        sql(conn, 'DELETE FROM sessions WHERE token_hash=?', hashlib.sha256(token.encode()).hexdigest())
    response.delete_cookie(AUTH_COOKIE, path='/')
    return {'ok': True}


@app.get('/api/bootstrap')
def bootstrap(user: dict = Depends(require_user)):
    with connection() as conn:
        item = one(conn, 'SELECT version, content, updated_at, updated_by FROM knowledge WHERE id=1')
    return {'me': {'username':user['username'],'role':user['role']}, 'csrf':user['csrf_token'],
            'version':item['version'], 'chapters':json.loads(item['content']),
            'updated_at':item['updated_at'],'updated_by':item['updated_by']}


@app.get('/api/version')
def version(user: dict = Depends(require_user)):
    with connection() as conn:
        item = one(conn, 'SELECT version,updated_at,updated_by FROM knowledge WHERE id=1')
    return item


@app.put('/api/knowledge')
def update_knowledge(body: KnowledgeUpdate, user: dict = Depends(require_edit)):
    chapters = validate_chapters(body.chapters)
    content = json.dumps(chapters, ensure_ascii=False, separators=(',', ':'))
    new_version = body.version + 1
    with connection() as conn:
        res = sql(conn, 'UPDATE knowledge SET version=?,content=?,updated_at=?,updated_by=? WHERE id=1 AND version=?', new_version, content, now(), user['username'], body.version)
        if res.rowcount != 1:
            latest = one(conn, 'SELECT version,updated_by,updated_at FROM knowledge WHERE id=1')
            return JSONResponse({'error':'conflict','message':'其他协作者已更新，请保留本地备份并刷新', 'latest':latest}, status_code=409)
        sql(conn, 'INSERT INTO revisions VALUES (?,?,?,?,?)', new_version, content, user['username'], now(), body.summary or '更新方法论')
    return {'ok':True, 'version':new_version, 'updated_by':user['username']}


@app.get('/api/history')
def history(user: dict = Depends(require_user)):
    with connection() as conn:
        items = rows(conn, 'SELECT version,author,created_at,summary FROM revisions ORDER BY version DESC LIMIT 100')
    return {'items':items}


@app.get('/api/history/{revision}')
def history_data(revision: int, user: dict = Depends(require_user)):
    with connection() as conn:
        item = one(conn, 'SELECT version,content,author,created_at,summary FROM revisions WHERE version=?', revision)
    if not item: raise HTTPException(404, '版本不存在')
    item['chapters'] = json.loads(item.pop('content'))
    return item


@app.post('/api/history/{revision}/restore')
def restore(revision: int, req: Request, user: dict = Depends(require_admin)):
    with connection() as conn:
        old = one(conn, 'SELECT content FROM revisions WHERE version=?', revision)
        cur = one(conn, 'SELECT version FROM knowledge WHERE id=1')
        if not old: raise HTTPException(404, '版本不存在')
        new = cur['version'] + 1
        sql(conn, 'UPDATE knowledge SET version=?,content=?,updated_at=?,updated_by=? WHERE id=1', new, old['content'], now(), user['username'])
        sql(conn, 'INSERT INTO revisions VALUES (?,?,?,?,?)', new, old['content'], user['username'], now(), f'恢复历史版本 v{revision}')
    return {'ok':True,'version':new}


@app.get('/api/export')
def export(user: dict = Depends(require_user)):
    with connection() as conn:
        item = one(conn, 'SELECT version,content FROM knowledge WHERE id=1')
    payload = json.dumps({'version':item['version'],'chapters':json.loads(item['content'])},ensure_ascii=False,indent=2)
    return Response(payload,media_type='application/json',headers={'Content-Disposition':'attachment; filename="knowledge-backup.json"'})


@app.get('/api/users')
def get_users(req: Request, user:dict = Depends(require_user)):
    if user['role'] != 'admin': raise HTTPException(403, '没有权限')
    with connection() as conn:
        items = rows(conn, 'SELECT username,role,active,created_at FROM users ORDER BY created_at')
    return {'items':items}


@app.post('/api/users')
def add_user(data:UserCreate, user:dict = Depends(require_admin)):
    if not re.fullmatch(r'[A-Za-z0-9_.@-]{3,64}', data.username): raise HTTPException(422,'用户名格式不合法')
    if data.role not in ('admin','editor','viewer'): raise HTTPException(422,'角色无效')
    if len(data.password)<12 or len(data.password)>128: raise HTTPException(422,'密码应为12-128位')
    with connection() as conn:
        if one(conn, 'SELECT username FROM users WHERE username=?', data.username): raise HTTPException(409,'账户已存在')
        sql(conn,'INSERT INTO users VALUES (?,?,?,?,?)',data.username,password_hash(data.password),data.role,1,now())
    return {'ok':True}


@app.patch('/api/users/{username}')
def patch_user(username:str, data:UserPatch, user:dict = Depends(require_admin)):
    with connection() as conn:
        existing = one(conn,'SELECT * FROM users WHERE username=?',username)
        if not existing:raise HTTPException(404,'用户不存在')
        role = data.role if data.role is not None else existing['role']
        active = int(data.active) if data.active is not None else existing['active']
        if role not in ('admin','editor','viewer'): raise HTTPException(422,'角色无效')
        if (role != 'admin' or active == 0) and existing['role']=='admin' and existing['active']:
            admins = one(conn,"SELECT COUNT(*) AS n FROM users WHERE role='admin' AND active=1")['n']
            if admins <= 1: raise HTTPException(409,'不能停用最后一个管理员')
        if username == user['username'] and (role!='admin' or not active):
            raise HTTPException(409,'不能自行取消当前管理员权限')
        if data.password is not None:
            if not 12<=len(data.password)<=128:raise HTTPException(422,'新密码应为12-128位')
            sql(conn,'UPDATE users SET password_hash=?,role=?,active=? WHERE username=?',password_hash(data.password),role,active,username)
            sql(conn,'DELETE FROM sessions WHERE username=?', username)
        else:
            sql(conn,'UPDATE users SET role=?,active=? WHERE username=?',role,active,username)
            if not active: sql(conn,'DELETE FROM sessions WHERE username=?',username)
    return {'ok':True}


@app.get('/')
def root(request:Request):
    if not session_user(request):
        return RedirectResponse('/login',status_code=303)
    return FileResponse(STATIC/'index.html',media_type='text/html')


@app.get('/login')
def login_page(request:Request):
    if session_user(request):return RedirectResponse('/',status_code=303)
    return FileResponse(STATIC/'login.html',media_type='text/html')


@app.get('/admin')
def admin_page(request:Request):
    user = session_user(request)
    if not user:return RedirectResponse('/login',status_code=303)
    if user['role']!='admin':return RedirectResponse('/',status_code=303)
    return FileResponse(STATIC/'admin.html',media_type='text/html')


@app.get("/history")
def history_page(request:Request):
    if not session_user(request):return RedirectResponse("/login",status_code=303)
    return FileResponse(STATIC/"history.html",media_type="text/html")
