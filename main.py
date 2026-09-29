import asyncio, base64, hashlib, ipaddress, json, os, secrets, struct, time, uuid as U
from pathlib import Path
from fastapi import FastAPI, WebSocket, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from urllib.parse import quote
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

ADMIN = os.getenv("ADMIN_PASSWORD") or secrets.token_urlsafe(8)
DOMAIN = os.getenv("RAILWAY_PUBLIC_DOMAIN", "localhost:8000")
WS_PATH = os.getenv("WS_PATH", "/ws")
DB = Path(os.getenv("DATA_FILE", "data.json"))
GB = 1024 ** 3
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
links, sessions, live, history = {}, set(), {}, []

def save():
    DB.write_text(json.dumps(links))

@app.on_event("startup")
async def start():
    print(f"ADMIN PASSWORD: {ADMIN}" if not os.getenv("ADMIN_PASSWORD") else "panel ready")
    if DB.exists():
        links.update(json.loads(DB.read_text()))
    async def tick():
        while True:
            await asyncio.sleep(60)
            history.append([int(time.time()), sum(l["used"] for l in links.values())])
            del history[:-60]
            save()
    asyncio.create_task(tick())

def auth(req: Request):
    if req.cookies.get("sid") not in sessions:
        raise HTTPException(401)

def over(l):
    return not l["enabled"] or (l["quota"] and l["used"] >= l["quota"])

def blocked(host):
    if host.endswith(".internal") or host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False

class Stream:
    def __init__(s, ws, buf=b""):
        s.ws, s.buf = ws, buf
    async def read(s, n):
        while len(s.buf) < n:
            s.buf += await s.ws.receive_bytes()
        out, s.buf = s.buf[:n], s.buf[n:]
        return out

async def read_addr(s):
    t = (await s.read(1))[0]
    if t == 1: h = str(ipaddress.IPv4Address(await s.read(4)))
    elif t == 3: h = (await s.read((await s.read(1))[0])).decode()
    elif t == 4: h = str(ipaddress.IPv6Address(await s.read(16)))
    else: raise ValueError
    return h, struct.unpack(">H", await s.read(2))[0]

async def relay(uid, l, host, port, rd, wr, first=b""):
    if blocked(host):
        return
    r, w = await asyncio.open_connection(host, port)
    live[uid] = live.get(uid, 0) + 1
    try:
        if first:
            w.write(first); l["used"] += len(first)
        async def up():
            while not over(l):
                b = await rd()
                l["used"] += len(b); w.write(b); await w.drain()
        async def down():
            while not over(l):
                b = await r.read(65536)
                if not b: return
                l["used"] += len(b); await wr(b)
        ts = [asyncio.create_task(up()), asyncio.create_task(down())]
        await asyncio.wait(ts, return_when=asyncio.FIRST_COMPLETED)
        for t in ts: t.cancel()
    finally:
        live[uid] = max(0, live.get(uid, 1) - 1); w.close()

async def shut(ws):
    try: await ws.close()
    except Exception: pass

@app.websocket(WS_PATH)
async def vless(ws: WebSocket):
    await ws.accept()
    try:
        d = await ws.receive_bytes()
        uid = str(U.UUID(bytes=d[1:17])); l = links.get(uid)
        if not l or over(l): return
        i = 18 + d[17]
        cmd, port, t = d[i], struct.unpack(">H", d[i + 1:i + 3])[0], d[i + 3]
        i += 4
        if t == 1: host = str(ipaddress.IPv4Address(d[i:i + 4])); i += 4
        elif t == 2: n = d[i]; host = d[i + 1:i + 1 + n].decode(); i += 1 + n
        elif t == 3: host = str(ipaddress.IPv6Address(d[i:i + 16])); i += 16
        else: return
        if cmd != 1: return
        head = [bytes([d[0], 0])]
        async def wr(b):
            await ws.send_bytes((head.pop() if head else b"") + b)
        await relay(uid, l, host, port, ws.receive_bytes, wr, d[i:])
    except Exception:
        pass
    finally:
        await shut(ws)

@app.websocket("/tj")
async def trojan(ws: WebSocket):
    await ws.accept()
    try:
        s = Stream(ws)
        h = (await s.read(56)).decode()
        uid = next((k for k in links if hashlib.sha224(k.encode()).hexdigest() == h), None)
        l = links.get(uid)
        if not l or over(l): return
        await s.read(2)
        cmd = (await s.read(1))[0]
        host, port = await read_addr(s)
        await s.read(2)
        if cmd != 1: return
        await relay(uid, l, host, port, ws.receive_bytes, ws.send_bytes, s.buf)
    except Exception:
        pass
    finally:
        await shut(ws)

def ss_key(pw):
    k = p = b""
    while len(k) < 32:
        p = hashlib.md5(p + pw.encode()).digest(); k += p
    return k[:32]

def subkey(key, salt):
    return HKDF(algorithm=hashes.SHA1(), length=32, salt=salt, info=b"ss-subkey").derive(key)

class Box:
    def __init__(s, key):
        s.a, s.n = AESGCM(key), 0
    def nonce(s):
        n = s.n.to_bytes(12, "little"); s.n += 1; return n
    def dec(s, b): return s.a.decrypt(s.nonce(), b, None)
    def enc(s, b): return s.a.encrypt(s.nonce(), b, None)

@app.websocket("/ss")
async def shadow(ws: WebSocket):
    await ws.accept()
    try:
        s = Stream(ws)
        salt, first = await s.read(32), await s.read(18)
        uid = l = box = None
        for k, v in links.items():
            b = Box(subkey(ss_key(k), salt))
            try: n = int.from_bytes(b.dec(first), "big") & 0x3FFF
            except Exception: continue
            uid, l, box = k, v, b
            break
        if not l or over(l): return
        p = Stream(None, box.dec(await s.read(n + 16)))
        host, port = await read_addr(p)
        key, sbox = ss_key(uid), []
        async def rd():
            m = int.from_bytes(box.dec(await s.read(18)), "big") & 0x3FFF
            return box.dec(await s.read(m + 16))
        async def wr(b):
            out = b""
            if not sbox:
                rs = os.urandom(32); sbox.append(Box(subkey(key, rs))); out = rs
            for j in range(0, len(b), 0x3FFF):
                c = b[j:j + 0x3FFF]
                out += sbox[0].enc(len(c).to_bytes(2, "big")) + sbox[0].enc(c)
            await ws.send_bytes(out)
        await relay(uid, l, host, port, rd, wr, p.buf)
    except Exception:
        pass
    finally:
        await shut(ws)

def urls(uid, name):
    n, D = quote(name), DOMAIN
    tls = f"security=tls&sni={D}&type=ws&host={D}"
    ss = base64.urlsafe_b64encode(f"aes-256-gcm:{uid}".encode()).decode().rstrip("=")
    plug = quote(f"v2ray-plugin;tls;host={D};path=/ss", safe="")
    return {"vless": f"vless://{uid}@{D}:443?encryption=none&{tls}&path={quote(WS_PATH, safe='')}#{n}",
            "trojan": f"trojan://{uid}@{D}:443?{tls}&path=%2Ftj#{n}",
            "ss": f"ss://{ss}@{D}:443?plugin={plug}#{n}"}

@app.post("/api/login")
async def login(req: Request):
    if not secrets.compare_digest((await req.json()).get("password", ""), ADMIN):
        raise HTTPException(401)
    sid = secrets.token_urlsafe(24); sessions.add(sid)
    res = JSONResponse({"ok": 1})
    res.set_cookie("sid", sid, httponly=True, secure=DOMAIN != "localhost:8000", samesite="strict", max_age=86400 * 7)
    return res

@app.get("/api/state", dependencies=[Depends(auth)])
def state():
    rows = [{"id": k, **v, "live": live.get(k, 0), "urls": urls(k, v["name"])} for k, v in links.items()]
    return {"links": rows, "live": sum(live.values()), "total": sum(l["used"] for l in links.values()), "history": history}

@app.post("/api/links", dependencies=[Depends(auth)])
async def add(req: Request):
    b = await req.json()
    links[str(U.uuid4())] = {"name": (b.get("name") or "user")[:40], "quota": int(float(b.get("gb") or 0) * GB),
                             "used": 0, "enabled": True, "created": int(time.time())}
    save(); return {"ok": 1}

@app.patch("/api/links/{uid}", dependencies=[Depends(auth)])
async def toggle(uid: str, req: Request):
    b = await req.json()
    if uid not in links: raise HTTPException(404)
    if "enabled" in b: links[uid]["enabled"] = bool(b["enabled"])
    if b.get("reset"): links[uid]["used"] = 0
    save(); return {"ok": 1}

@app.delete("/api/links/{uid}", dependencies=[Depends(auth)])
def remove(uid: str):
    links.pop(uid, None); save(); return {"ok": 1}

@app.get("/", response_class=HTMLResponse)
def home():
    return "<h1>It works</h1>"

PAGE = r"""<!doctype html><html dir=rtl lang=fa><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Panel</title>
<style>
body{font:15px Tahoma,sans-serif;margin:0 auto;padding:16px;max-width:720px;background:#f2f4f8;color:#16223b}
@media(prefers-color-scheme:dark){body{background:#141a2b;color:#e8ecf6}}
input,button{font:inherit;color:inherit;background:0;border:1px solid #8886;border-radius:6px;padding:7px 10px}
input{flex:1;min-width:0}form,.a{display:flex;gap:6px;flex-wrap:wrap;margin:10px 0}
.it{border-top:1px solid #8886;padding:12px 0}.b{height:6px;background:#8884;border-radius:3px;overflow:hidden;margin:6px 0}
.b i{display:block;height:100%;background:#2b59ff}.m{opacity:.7;font-size:13px}.r{color:#c2410c}
</style>
<div id=lg hidden><form onsubmit=lgn(event)><input id=pw type=password placeholder=رمز><button>ورود</button></form></div>
<div id=ap hidden><h2 id=t></h2><div class=m id=lv></div>
<form onsubmit=ad(event)><input id=nm placeholder=نام><input id=gb type=number step=any placeholder="گیگ (خالی = نامحدود)"><button>ساخت</button></form><div id=ls></div></div>
<script>
const $=i=>document.getElementById(i),F=b=>b>=2**30?(b/2**30).toFixed(2)+" GB":(b/2**20).toFixed(1)+" MB";
const api=async(u,m="GET",b)=>{const r=await fetch(u,{method:m,headers:{"Content-Type":"application/json"},body:b&&JSON.stringify(b)});if(r.status==401)throw 1;return r.json()};
async function lgn(e){e.preventDefault();try{await api("/api/login","POST",{password:$("pw").value});load()}catch{alert("رمز اشتباه")}}
async function ad(e){e.preventDefault();await api("/api/links","POST",{name:$("nm").value,gb:$("gb").value});e.target.reset();load()}
const act=async(i,b)=>{await api("/api/links/"+i,"PATCH",b);load()};
const del=async i=>{if(confirm("حذف؟")){await api("/api/links/"+i,"DELETE");load()}};
async function load(){let s;try{s=await api("/api/state")}catch{$("ap").hidden=1;$("lg").hidden=0;return}
$("lg").hidden=1;$("ap").hidden=0;$("t").textContent=F(s.total);$("lv").textContent=s.live+" اتصال فعال";$("ls").innerHTML="";
s.links.forEach(l=>{const d=document.createElement("div");d.className="it";const p=l.quota?Math.min(100,l.used/l.quota*100):0;
d.innerHTML=`<b></b> <span class=m>${l.live} اتصال</span>${l.quota?`<div class=b><i style="width:${p}%"></i></div>`:""}<div class=m>${F(l.used)} / ${l.quota?F(l.quota):"∞"}${l.enabled?"":" <span class=r>خاموش</span>"}</div><div class=a></div>`;
d.querySelector("b").textContent=l.name;const a=d.querySelector(".a");
const btn=(t,f)=>{const x=document.createElement("button");x.textContent=t;x.onclick=f;a.append(x)};
for(const k of["vless","trojan","ss"])btn(k,e=>{navigator.clipboard.writeText(l.urls[k]);e.target.textContent="✓"});
btn(l.enabled?"خاموش":"روشن",()=>act(l.id,{enabled:!l.enabled}));btn("صفر",()=>act(l.id,{reset:1}));btn("حذف",()=>del(l.id));
$("ls").append(d)})}
load();setInterval(()=>{if(!$("ap").hidden)load()},10000);
</script>"""

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return PAGE
