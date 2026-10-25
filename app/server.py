"""PS3 Guardian app: SMS -> detector -> advisor -> API + phone page.

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

The web page (/ and /check) has no login: keep it on your own network. The
Android companion uses POST /sms, which needs the pairing token in the
X-Guardian-Token header (GUARDIAN_TOKEN on the Pi; scripts/run_pi.sh creates
one) and logs each message for measuring (app/sms_log.py).
"""
import os
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from advisor.advise import Advisor
from advisor.backends import backend_from_env

JOB_TTL_S = 900
MAX_JOBS = 200


class CheckIn(BaseModel):
    message: str = Field(..., min_length=1, max_length=2000)
    sender: Optional[str] = Field(None, max_length=64)
    language: str = Field("en", pattern="^(en|hi)$")
    test: bool = False                  # /sms: a test from the phone's button, not logged


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


def create_app(detector=None, advisor=None, sms_log=None):
    if detector is None:
        from detectors.sms.detector import SmsDetector
        detector = SmsDetector()
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
        finding = detector.check(req.message, sender=req.sender, language=req.language)
        return respond(finding, wait, t0, time.time())

    @app.post("/sms")
    def sms(req: CheckIn, x_guardian_token: Optional[str] = Header(None)):
        """For the Android companion: the SMS as received, with its sender ID."""
        token = os.environ.get("GUARDIAN_TOKEN", "")
        if not token:
            raise HTTPException(status_code=503, detail="no pairing token on the Pi: set GUARDIAN_TOKEN")
        if not secrets.compare_digest((x_guardian_token or "").encode(), token.encode()):
            raise HTTPException(status_code=401, detail="wrong pairing token")
        t0 = time.time()
        finding = detector.check(req.message, sender=req.sender, language=req.language)
        text_only = detector.check(req.message, sender=None, language=req.language)
        t1 = time.time()
        out = respond(finding, False, t0, t1)
        out["text_only"] = {"verdict": text_only.verdict, "score": text_only.score}
        out["log_id"] = None if req.test else (sms_log or default_log()).add(req.message, req.sender,
                                                                             finding, text_only)
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

    @app.get("/health")
    def health():
        h = {"ok": True, "backend": advisor.backend.name, "jobs_pending": jobs.queued()}
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
#llm{border-left:3px solid var(--accent);padding-left:10px}
</style></head><body><main>
<h1>Check a message</h1>
<div class="card">
<textarea id="msg" placeholder="Paste an SMS or WhatsApp message"></textarea>
<div class="row"><input id="sender" placeholder="Sender ID or number (optional)">
<select id="lang"><option value="en">English</option><option value="hi">हिन्दी</option></select></div>
<button id="go">Check</button></div>
<div class="card" id="out" hidden>
<div id="head"></div><p id="what"></p><p id="why"></p>
<p class="muted" id="llm" hidden></p>
<ol id="steps"></ol><p class="muted" id="meta"></p></div>
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
    $('meta').textContent=`score ${f.score} | ${f.category} | backend ${d.backend}`
      +` | detect ${d.timing_ms.detect} ms`;
    $('llm').hidden=!d.explain;
    if(d.explain){$('llm').textContent='Llama is writing a plain-language explanation on this device...';
      follow(d.explain.id,Date.now());}
  }catch(e){$('out').hidden=false;$('head').textContent='Error: '+e;}
  finally{$('go').disabled=false;$('go').textContent='Check';}
};
</script></main></body></html>"""

app = create_app()
