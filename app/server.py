"""PS3 Guardian, vertical slice: SMS -> detector -> Llama advisor -> API + web page.

Run from the repo root:
    uvicorn app.server:app --host 0.0.0.0 --port 8000
then open http://<pi-or-laptop-ip>:8000 from any phone on the same network.

Backend is chosen by environment variables (see advisor/backends.py):
    ADVISOR_BACKEND=template      (default, no LLM, works anywhere)
    ADVISOR_BACKEND=llama_main    (Llama 3.2 on the Pi through ExecuTorch)

No authentication yet: keep it on your lab network. Add a pairing token
before the Android companion talks to it.
"""
import time
from typing import Optional

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from advisor.advise import Advisor
from advisor.backends import backend_from_env
from detectors.sms.detector import SmsDetector

app = FastAPI(title="PS3 Guardian - vertical slice")
_detector = SmsDetector()
_advisor = Advisor(backend=backend_from_env())


class CheckIn(BaseModel):
    message: str = Field(..., min_length=1, max_length=2000)
    sender: Optional[str] = Field(None, max_length=64)
    language: str = Field("en", pattern="^(en|hi)$")


@app.post("/check")
def check(req: CheckIn):
    t0 = time.time()
    finding = _detector.check(req.message, sender=req.sender, language=req.language)
    t1 = time.time()
    advice = _advisor.advise(finding)
    t2 = time.time()
    f = finding.to_dict()
    f.pop("raw_text", None)                       # never echo untrusted text back
    return {"finding": f, "advice": advice.to_dict(), "backend": _advisor.backend.name,
            "timing_ms": {"detect": round((t1 - t0) * 1000, 1),
                          "advise": round((t2 - t1) * 1000, 1)}}


@app.get("/health")
def health():
    return {"ok": True, "backend": _advisor.backend.name}


@app.get("/", response_class=HTMLResponse)
def index():
    return PAGE


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
</style></head><body><main>
<h1>Check a message</h1>
<div class="card">
<textarea id="msg" placeholder="Paste an SMS or WhatsApp message"></textarea>
<div class="row"><input id="sender" placeholder="Sender ID or number (optional)">
<select id="lang"><option value="en">English</option><option value="hi">हिन्दी</option></select></div>
<button id="go">Check</button></div>
<div class="card" id="out" hidden>
<div id="head"></div><p id="what"></p><p id="why"></p><ol id="steps"></ol><p class="muted" id="meta"></p></div>
<script>
const $=id=>document.getElementById(id);
$('go').onclick=async()=>{
  const body={message:$('msg').value,sender:$('sender').value||null,language:$('lang').value};
  if(!body.message.trim())return;
  $('go').disabled=true;$('go').textContent='Checking...';
  try{
    const r=await fetch('/check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const d=await r.json();const a=d.advice,f=d.finding,m=a.metrics||{};
    $('out').hidden=false;$('head').textContent=a.headline;$('head').className=f.verdict;
    $('what').textContent=a.what;$('why').textContent=a.why;
    $('steps').replaceChildren(...a.steps.map(s=>{const li=document.createElement('li');li.textContent=s;return li;}));
    $('meta').textContent=`score ${f.score} | ${f.category} | backend ${d.backend} | source ${a.source}`
      +(m.ttft_s!==undefined?` | first token ${m.ttft_s}s | ${m.decode_tok_s??'?'} tok/s`:'')
      +` | detect ${d.timing_ms.detect} ms, advise ${d.timing_ms.advise} ms`;
  }catch(e){$('out').hidden=false;$('head').textContent='Error: '+e;}
  finally{$('go').disabled=false;$('go').textContent='Check';}
};
</script></main></body></html>"""
