"""PS3 Guardian app: SMS or link -> detectors -> advisor -> API + phone page.

Run from the repo root:
    uvicorn app.server:app --host 0.0.0.0 --port 8000
then open http://<pi-or-laptop-ip>:8000 from any phone on the same network.

Backend is chosen by environment variables (see advisor/backends.py):
    ADVISOR_BACKEND=template      (default, no LLM, works anywhere)
    ADVISOR_BACKEND=service       (persistent Llama service on the Pi: the fast path)
    ADVISOR_BACKEND=llama_main    (one llama_main run per alert: slow fallback)

With an LLM backend, POST /check answers at once with the playbook template
and a job id; the Llama explanation is written in the background and fetched
from GET /explain/{id} once the validator has checked it. Llama tokens are
never streamed to the user unchecked.

POST /check takes a message (the links in it are checked too) or a single link;
POST /url takes a link. GET /alerts lists the network monitor's alerts
(detectors/net/monitor.py writes them to logs/net_alerts.jsonl) with their advice.
Lab devices (the ESP32, esp32/ps3_lab_device) post their readings to POST /iot and
get back the test mode the page asked for (GET /iot, POST /iot/mode; app/lab_devices.py).

The web page (/ and /check), /alerts, GET /iot and /iot/mode have no login: keep them
on your own network (the lab Wi-Fi is WPA2). The Android companion uses POST /sms and
lab devices POST /iot; both need the pairing token in the X-Guardian-Token header
(GUARDIAN_TOKEN on the Pi; scripts/run_pi.sh creates one). /sms logs each message for
measuring (app/sms_log.py).
"""
import json
import os
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from advisor.advise import Advisor
from advisor.backends import backend_from_env
from advisor.findings import Finding
from app.lab_devices import MODES, LabDevices, clean_readings

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NET_ALERTS = os.path.join(ROOT, "logs", "net_alerts.jsonl")
NET_STATE = os.path.join(ROOT, "data", "net", "devices.json")     # what the monitor learned per device
LEARN_S = 2 * 3600                                                 # the monitor's learning time per device
JOB_TTL_S = 900
MAX_JOBS = 200


class CheckIn(BaseModel):
    message: str = Field(..., min_length=1, max_length=2000)
    sender: Optional[str] = Field(None, max_length=64)
    language: str = Field("en", pattern="^(en|hi)$")
    test: bool = False                  # /sms: a test from the phone's button, not logged
    # /sms only, sent by the Android companion:
    channel: str = Field("sms", pattern="^(sms|chat)$")     # chat: RCS, MMS or WhatsApp, read from a notification
    app: Optional[str] = Field(None, max_length=40, pattern="^[a-z_]+$")   # the chat app: messages, whatsapp
    device: Optional[str] = Field(None, max_length=32)      # the phone's name typed in the app, e.g. "A"


class UrlIn(BaseModel):
    url: str = Field(..., min_length=1, max_length=2000)
    language: str = Field("en", pattern="^(en|hi)$")


class LabReport(BaseModel):
    """POST /iot from a lab device: its readings and the mode it is in."""
    device: str = Field(..., pattern=r"^[A-Za-z0-9_-]{1,32}$")
    readings: dict = Field(default_factory=dict)
    mode: str = Field("normal", pattern="^[a-z]{1,16}$")


class LabMode(BaseModel):
    device: str = Field(..., pattern=r"^[A-Za-z0-9_-]{1,32}$")
    mode: str = Field(..., pattern="^[a-z]{1,16}$")


def require_token(given):
    token = os.environ.get("GUARDIAN_TOKEN", "")
    if not token:
        raise HTTPException(status_code=503, detail="no pairing token on the Pi: set GUARDIAN_TOKEN")
    if not secrets.compare_digest((given or "").encode(), token.encode()):
        raise HTTPException(status_code=401, detail="wrong pairing token")


class LearnedState:
    """When the network monitor started learning each device (data/net/devices.json, which it
    saves every 10 minutes), re-read only when the file changes."""

    def __init__(self, path):
        self.path, self.mtime, self.first = path, None, {}

    def first_seen(self, ip):
        try:
            mtime = os.path.getmtime(self.path)
            if mtime != self.mtime:
                with open(self.path, encoding="utf-8") as f:
                    data = json.load(f)
                self.first = {k: v.get("first_ms", 0) / 1000 for k, v in data.items() if isinstance(v, dict)}
                self.mtime = mtime
        except (OSError, ValueError, AttributeError):
            pass
        return self.first.get(ip)


def single_link(text):
    """The link, if the text is one link and nothing else ("hdfc-kyc.top/x"), else None."""
    from detectors.url.links import parse_link
    s = (text or "").strip()
    if not s or any(c.isspace() for c in s):
        return None
    return parse_link(s if "://" in s else "http://" + s) and s


class JobStore:
    """In-memory explanation jobs (one LLM at a time, so a single worker thread)."""

    def __init__(self):
        self.jobs, self.lock = {}, threading.Lock()
        self.pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="llm")

    def submit(self, fn):
        job_id = secrets.token_urlsafe(9)
        now = time.time()
        with self.lock:
            for k in [k for k, j in self.jobs.items() if now - j["created"] > JOB_TTL_S]:
                del self.jobs[k]
            while len(self.jobs) >= MAX_JOBS:
                del self.jobs[next(iter(self.jobs))]
            self.jobs[job_id] = {"status": "pending", "created": now}

        def run():
            try:
                advice = fn()
                result = {"status": "done" if advice.source == "llm" else "fallback",
                          "advice": advice.to_dict()}
            except Exception as e:                      # never leave a job hanging
                result = {"status": "failed", "error": type(e).__name__}
            with self.lock:
                if job_id in self.jobs:
                    self.jobs[job_id].update(result, finished=time.time())

        self.pool.submit(run)
        return job_id

    def get(self, job_id):
        with self.lock:
            j = self.jobs.get(job_id)
            return dict(j) if j else None

    def queued(self):
        with self.lock:
            return sum(1 for j in self.jobs.values() if j["status"] == "pending")


_DEFAULT_LOG = None


def default_log():
    global _DEFAULT_LOG
    if _DEFAULT_LOG is None:
        from app.sms_log import SmsLog
        _DEFAULT_LOG = SmsLog()
    return _DEFAULT_LOG


def _public_finding(finding):
    f = finding.to_dict()
    f.pop("raw_text", None)                       # never echo untrusted text back
    return f


def read_alerts(path, limit=50, max_bytes=2_000_000):
    """The newest `limit` network alerts in the monitor's file, newest first."""
    if not path or not os.path.exists(path):
        return []
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        f.seek(max(0, size - max_bytes))
        lines = f.read().decode("utf-8", errors="replace").splitlines()
    if size > max_bytes:
        lines = lines[1:]                          # the first line may be cut
    out = []
    for line in reversed(lines):
        try:
            item = json.loads(line)
            Finding(**item["finding"])
        except (ValueError, KeyError, TypeError):
            continue
        out.append(item)
        if len(out) >= limit:
            break
    return out


def create_app(detector=None, advisor=None, sms_log=None, url_detector=None, net_alerts=None,
               lab=None, net_state=None):
    if detector is None:
        from detectors.sms.detector import SmsDetector
        detector = SmsDetector()
    if url_detector is None:
        url_detector = getattr(detector, "url", None)
        if url_detector is None:
            from detectors.url.detector import UrlDetector
            url_detector = UrlDetector()
    advisor = advisor or Advisor(backend=backend_from_env())
    jobs = JobStore()
    app = FastAPI(title="PS3 Guardian")

    def respond(finding, wait, t0, t1):
        explain = None
        if advisor.needs_llm(finding) and not wait:
            advice = advisor.quick(finding)
            ahead = jobs.queued()
            explain = {"id": jobs.submit(lambda: advisor.explain(finding)), "status": "pending",
                       "queued_ahead": ahead}
        else:
            advice = advisor.advise(finding)
        t2 = time.time()
        return {"finding": _public_finding(finding), "advice": advice.to_dict(),
                "backend": advisor.backend.name, "explain": explain,
                "timing_ms": {"detect": round((t1 - t0) * 1000, 1),
                              "advise": round((t2 - t1) * 1000, 1)}}

    @app.post("/check")
    def check(req: CheckIn, wait: bool = False):
        t0 = time.time()
        if single_link(req.message) and not req.sender:        # a pasted link on its own
            finding = url_detector.check(req.message, language=req.language)
        else:
            finding = detector.check(req.message, sender=req.sender, language=req.language)
        return respond(finding, wait, t0, time.time())

    @app.post("/url")
    def url(req: UrlIn, wait: bool = False):
        """One link: is it safe to open?"""
        if not single_link(req.url):
            raise HTTPException(status_code=422, detail="send one link, without spaces")
        t0 = time.time()
        finding = url_detector.check(req.url, language=req.language)
        return respond(finding, wait, t0, time.time())

    @app.post("/sms")
    def sms(req: CheckIn, x_guardian_token: Optional[str] = Header(None)):
        """For the Android companion: the SMS as received, with its sender ID."""
        require_token(x_guardian_token)
        from detectors.sms.detector import classify_sender
        sender = req.sender
        if req.channel == "chat" and classify_sender(sender).kind != "mobile":
            sender = None       # a chat shows a contact or brand name, not a registered sender ID
        t0 = time.time()
        finding = detector.check(req.message, sender=sender, language=req.language)
        text_only = detector.check(req.message, sender=None, language=req.language)
        t1 = time.time()
        out = respond(finding, False, t0, t1)
        out["text_only"] = {"verdict": text_only.verdict, "score": text_only.score}
        out["log_id"] = None if req.test else (sms_log or default_log()).add(
            req.message, req.sender, finding, text_only, channel=req.channel, app=req.app, device=req.device)
        return out

    @app.get("/explain/{job_id}")
    def explain(job_id: str):
        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="unknown or expired job")
        out = {"status": job["status"], "advice": job.get("advice")}
        if "finished" in job:
            out["seconds"] = round(job["finished"] - job["created"], 1)
        return out

    alerts_path = net_alerts or os.environ.get("NET_ALERTS", NET_ALERTS)

    @app.get("/alerts")
    def alerts(limit: int = 50):
        """Network alerts, newest first, each with the playbook's advice."""
        out = []
        for item in read_alerts(alerts_path, max(1, min(limit, 200))):
            finding = Finding(**item["finding"])
            out.append({"time": item.get("time"), "finding": _public_finding(finding),
                        "advice": advisor.quick(finding).to_dict()})
        return {"alerts": out}

    lab = lab if lab is not None else LabDevices()
    learned = LearnedState(net_state or os.environ.get("NET_STATE", NET_STATE))

    @app.post("/iot")
    def iot_report(req: LabReport, request: Request, x_guardian_token: Optional[str] = Header(None)):
        """A lab device's readings (every 15 s); the answer is the mode it should be in."""
        require_token(x_guardian_token)
        try:
            readings = clean_readings(req.readings)
            return lab.report(req.device, request.client.host if request.client else "", readings, req.mode)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))

    @app.get("/iot")
    def iot_list():
        """Lab devices for the page: readings, test mode, and their latest network alerts."""
        devices, recent = lab.listing(), read_alerts(alerts_path, 200)
        now = time.time()
        for d in devices:
            first = learned.first_seen(d["ip"])
            d["learning_until"] = (time.strftime("%H:%M", time.localtime(first + LEARN_S))
                                   if first and first + LEARN_S > now else None)
            mine = [a for a in recent if a["finding"].get("entities", {}).get("device") == d["ip"]][:3]
            d["alerts"] = []
            for a in mine:
                finding = Finding(**a["finding"])
                d["alerts"].append({"time": a.get("time"), "verdict": finding.verdict,
                                    "headline": advisor.quick(finding).headline})
        return {"devices": devices, "modes": {k: v[0] for k, v in MODES.items()}}

    @app.post("/iot/mode")
    def iot_mode(req: LabMode):
        """Start a harmless test on a lab device, or stop it ("normal")."""
        try:
            return lab.set_mode(req.device, req.mode)
        except KeyError:
            raise HTTPException(status_code=404, detail="no lab device with that name has reported")
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))

    @app.get("/health")
    def health():
        h = {"ok": True, "backend": advisor.backend.name, "jobs_pending": jobs.queued(),
             "links": url_detector.info(),
             "net": {"alerts_file": os.path.exists(alerts_path),
                     "alerts_mb": round(os.path.getsize(alerts_path) / 1e6, 2) if os.path.exists(alerts_path) else 0}}
        if hasattr(advisor.backend, "health"):
            h["llm"] = advisor.backend.health()
        return h

    @app.get("/", response_class=HTMLResponse)
    def index():
        return PAGE

    return app


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PS3 Guardian</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--ink:#16181d;--muted:#5b6170;--line:#dfe2e8;
--danger:#b42318;--warn:#b54708;--ok:#067647;--accent:#2b59c3}
@media (prefers-color-scheme:dark){:root{--bg:#111318;--card:#1a1d24;--ink:#eceef2;
--muted:#a3a9b6;--line:#2b2f39;--danger:#f97066;--warn:#fdb022;--ok:#47cd89;--accent:#7aa2ff}}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:640px;margin:0 auto;padding:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin:12px 0}
textarea,input,select,button{font:inherit;width:100%;box-sizing:border-box;border:1px solid var(--line);
border-radius:8px;padding:10px;background:var(--card);color:var(--ink)}
textarea{min-height:110px}.row{display:flex;gap:8px;margin-top:8px}.row>*{flex:1}
button{background:var(--accent);color:#fff;border:0;cursor:pointer;margin-top:8px}
h1{font-size:20px;margin:8px 0}#head{font-weight:700;font-size:18px}
.dangerous{color:var(--danger)}.suspicious{color:var(--warn)}.safe{color:var(--ok)}
.muted{color:var(--muted);font-size:13px}ol{padding-left:20px}
.btns{display:flex;flex-wrap:wrap;gap:6px;margin-top:6px}.btns button{width:auto;flex:1 1 150px;margin-top:0;padding:8px;font-size:14px;background:transparent;color:var(--accent);border:1px solid var(--accent)}
.item{border-top:1px solid var(--line);padding:8px 0}
#llm{border-left:3px solid var(--accent);padding-left:10px}
</style></head><body><main>
<h1>Check a message or a link</h1>
<div class="card">
<textarea id="msg" placeholder="Paste an SMS, a WhatsApp message or a link"></textarea>
<div class="row"><input id="sender" placeholder="Sender ID or number (optional)">
<select id="lang"><option value="en">English</option><option value="hi">हिन्दी</option></select></div>
<button id="go">Check</button></div>
<div class="card" id="out" hidden>
<div id="head"></div><p id="what"></p><p id="why"></p>
<p class="muted" id="llm" hidden></p>
<ol id="steps"></ol><p class="muted" id="meta"></p></div>
<h1>Lab devices</h1>
<div class="card"><p class="muted" id="devnote">No lab device has reported yet.</p><div id="devices"></div></div>
<h1>Network alerts</h1>
<div class="card"><p class="muted" id="netnote">No network alerts yet.</p><div id="alerts"></div></div>
<script>
const $=id=>document.getElementById(id);
let poll=null;
function show(a){
  $('what').textContent=a.what;$('why').textContent=a.why;
  $('steps').replaceChildren(...a.steps.map(s=>{const li=document.createElement('li');li.textContent=s;return li;}));
}
function llmNote(a,secs){
  const m=a.metrics||{};
  if(a.source!=='llm'){
    const f=a.flags||[];const why=f.length?f[f.length-1].split('; template used')[0]:'';
    return 'Llama could not add an explanation'+(why?' (safety check: '+why+')':'')+', so this is the checked playbook text.';
  }
  if(m.cached){return 'Explained by Llama 3.2 on this device (saved answer, instant).';}
  return 'Explained by Llama 3.2 on this device in '+(secs??m.total_s??'?')+' s'
    +(m.decode_tok_s?' ('+m.decode_tok_s+' tokens/s)':'')+'.';
}
async function follow(id,t0){
  try{
    const r=await fetch('/explain/'+encodeURIComponent(id));const d=await r.json();
    if(d.status==='pending'){
      $('llm').textContent='Llama is writing a plain-language explanation on this device... '
        +Math.round((Date.now()-t0)/1000)+' s';
      poll=setTimeout(()=>follow(id,t0),1500);return;
    }
    if(d.advice){show(d.advice);$('llm').textContent=llmNote(d.advice,d.seconds);}
    else{$('llm').textContent='Llama explanation failed; the playbook text above is still correct.';}
  }catch(e){$('llm').textContent='Lost contact with the device: '+e;}
}
function alertItem(a){
  const f=a.finding,e=f.entities||{},div=document.createElement('div');
  div.style.borderTop='1px solid var(--line)';div.style.padding='8px 0';
  const h=document.createElement('div');h.className=f.verdict;h.style.fontWeight='600';h.textContent=a.advice.headline;
  const m=document.createElement('div');m.className='muted';
  m.textContent=(a.time||'')+' | device '+(e.device_name?e.device_name+' ('+e.device+')':e.device)+(e.peer?' | other side '+e.peer:'');
  const w=document.createElement('div');w.textContent=a.advice.why;
  const s=document.createElement('div');s.className='muted';s.textContent='First step: '+(a.advice.steps[0]||'');
  div.append(h,m,w,s);return div;
}
async function loadAlerts(){
  try{
    const r=await fetch('/alerts?limit=20');const d=await r.json();
    $('alerts').replaceChildren(...d.alerts.map(alertItem));
    $('netnote').textContent=d.alerts.length?'Newest first. The network monitor checks every device on the Wi-Fi of this Pi.':'No network alerts yet.';
  }catch(e){$('netnote').textContent='Could not load network alerts: '+e;}
}
loadAlerts();setInterval(loadAlerts,10000);
const READ={temp_c:['Temperature','°C'],humidity:['Humidity','%'],bmp_temp_c:['Temperature (BMP180)','°C'],
  pressure_hpa:['Pressure','hPa'],distance_cm:['Distance','cm'],knob:['Knob VR1',''],air_raw:['Air MQ-135 (raw)',''],
  rssi:['Wi-Fi signal','dBm'],heap_kb:['Free memory','KB']};
function reading(k,v){
  if(k==='obstacle')return 'IR sensor: '+(v?'something in front':'clear');
  if(k==='uptime_s'){const h=Math.floor(v/3600),m=Math.floor(v%3600/60);return 'Running for '+(h?h+' h ':'')+m+' min';}
  const r=READ[k]||[k,''];return r[0]+': '+v+(r[1]?' '+r[1]:'');
}
function deviceItem(d,modes){
  const div=document.createElement('div');div.className='item';
  const h=document.createElement('div');h.style.fontWeight='600';h.textContent=d.device+' ('+d.ip+')';
  const seen=document.createElement('div');seen.className='muted';
  seen.textContent='Last report '+d.seen_s_ago+' s ago'+(d.learning_until?' | the network monitor is learning its normal until '
    +d.learning_until+' (the beacon test needs that)':'');
  const r=document.createElement('div');r.textContent=Object.entries(d.readings).map(([k,v])=>reading(k,v)).join(' | ');
  const m=document.createElement('div');m.style.marginTop='6px';
  m.textContent=d.wanted==='normal'?'Mode: normal':'Test running: '+modes[d.wanted]+', '
    +Math.max(1,Math.ceil(d.seconds_left/60))+' min left'+(d.mode!==d.wanted?' (the device starts at its next report)':'');
  const b=document.createElement('div');b.className='btns';
  for(const [k,label] of Object.entries(modes)){
    if(k===d.wanted)continue;
    const btn=document.createElement('button');btn.textContent=k==='normal'?'Stop the test':label;
    btn.onclick=()=>setMode(d.device,k);b.append(btn);
  }
  div.append(h,seen,r,m,b);
  for(const a of d.alerts||[]){
    const x=document.createElement('div');x.className=a.verdict;x.style.fontSize='14px';
    x.textContent=(a.time||'')+'  '+a.headline;div.append(x);
  }
  return div;
}
async function loadDevices(){
  try{
    const r=await fetch('/iot');const d=await r.json();
    $('devices').replaceChildren(...d.devices.map(x=>deviceItem(x,d.modes)));
    $('devnote').textContent=d.devices.length?'Test modes only imitate what malware does on a network (look-ups of names that '
      +'do not exist, a small page fetched on a timer). Nothing is attacked, and each test stops by itself.'
      :'No lab device has reported yet: see docs/esp32-lab-device.md.';
  }catch(e){$('devnote').textContent='Could not load lab devices: '+e;}
}
async function setMode(device,mode){
  try{await fetch('/iot/mode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({device,mode})});}
  catch(e){}
  loadDevices();
}
loadDevices();setInterval(loadDevices,5000);
$('go').onclick=async()=>{
  const body={message:$('msg').value,sender:$('sender').value||null,language:$('lang').value};
  if(!body.message.trim())return;
  if(poll){clearTimeout(poll);poll=null;}
  $('go').disabled=true;$('go').textContent='Checking...';
  try{
    const r=await fetch('/check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const d=await r.json();const a=d.advice,f=d.finding;
    $('out').hidden=false;$('head').textContent=a.headline;$('head').className=f.verdict;
    show(a);
    const e=f.entities||{};
    const links=(e.links||[]).map(l=>l.link+' '+l.verdict).concat(e.link?[e.link+' ('+e.link_kind+')']:[]);
    $('meta').textContent=`score ${f.score} | ${f.category} | backend ${d.backend}`
      +` | detect ${d.timing_ms.detect} ms`+(links.length?' | links: '+links.join(', '):'');
    $('llm').hidden=!d.explain;
    if(d.explain){$('llm').textContent='Llama is writing a plain-language explanation on this device...';
      follow(d.explain.id,Date.now());}
  }catch(e){$('out').hidden=false;$('head').textContent='Error: '+e;}
  finally{$('go').disabled=false;$('go').textContent='Check';}
};
</script></main></body></html>"""

app = create_app()
