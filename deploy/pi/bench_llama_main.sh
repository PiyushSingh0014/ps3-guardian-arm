#!/usr/bin/env bash
# Measure ExecuTorch's llama_main on the Raspberry Pi; prints a Markdown table.
#
# Run on the Pi, from the folder that holds llama_main, llama3_2.pte and tokenizer.model:
#   cd ~/executorch-deployment && source setup_env.sh
#   bash ~/ps3-guardian/deploy/pi/bench_llama_main.sh                    # thread sweep 2 3 4, short prompt
#   bash ~/ps3-guardian/deploy/pi/bench_llama_main.sh ~/ps3-guardian/deploy/prompts/advisor_test2.txt 4
#
# Paste the printed table into eval/results_pi4.md.
# Optional settings: MAX_NEW_TOKENS (default 64), COOL_S = seconds to wait before
# each run so every run starts at a similar temperature (default 30),
# MODEL (default ./llama3_2.pte), TOKENIZER (default ./tokenizer.model).
set -euo pipefail

PROMPT_FILE="${1:-}"
if [ "$#" -gt 0 ]; then shift; fi
if [ "$#" -gt 0 ]; then THREADS=("$@"); else THREADS=(2 3 4); fi
MAX_NEW="${MAX_NEW_TOKENS:-64}"
COOL="${COOL_S:-30}"
MODEL="${MODEL:-./llama3_2.pte}"
TOKENIZER="${TOKENIZER:-./tokenizer.model}"

for f in ./llama_main "$MODEL" "$TOKENIZER"; do
  if [ ! -e "$f" ]; then echo "Missing $f. Run this from ~/executorch-deployment." >&2; exit 1; fi
done

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
if [ -z "$PROMPT_FILE" ]; then
  PROMPT_FILE="$TMP/short_prompt.txt"
  printf '%s' "Explain in one line why an SMS asking for your OTP is dangerous." > "$PROMPT_FILE"
fi

soc_temp() { vcgencmd measure_temp 2>/dev/null | sed "s/temp=//; s/'C/ °C/" || echo "n/a"; }
throttled() { vcgencmd get_throttled 2>/dev/null | sed 's/throttled=//' || echo "n/a"; }

echo "Prompt: $(basename "$PROMPT_FILE") | max new tokens: $MAX_NEW | greedy | $(date '+%Y-%m-%d %H:%M') | kernel $(uname -r)"
echo
echo "| Threads | Prompt tokens | Generated | Load (s) | First token (s) | Prefill (tok/s) | Decode (tok/s) | RSS (MiB) | Temp after | Throttled |"
echo "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"
for t in "${THREADS[@]}"; do
  sleep "$COOL"
  LOG="$TMP/run_$t.log"
  ./llama_main --model_path="$MODEL" --tokenizer_path="$TOKENIZER" --prompt_file="$PROMPT_FILE" \
    --max_new_tokens="$MAX_NEW" --temperature=0 --cpu_threads="$t" > "$LOG" 2>&1 || true
  cp "$LOG" "./bench_threads_$t.log"          # keep the raw output next to the model
  python3 - "$LOG" "$t" "$(soc_temp)" "$(throttled)" <<'PY'
import json, re, sys
log, threads, temp, thr = sys.argv[1:5]
text = open(log, encoding="utf-8", errors="replace").read()
m = re.search(r"PyTorchObserver (\{.*\})", text)
if not m:
    print(f"| {threads} | run failed, see bench_threads_{threads}.log | | | | | | | {temp} | {thr} |")
    sys.exit()
s = json.loads(m.group(1))
def secs(a, b):
    return (s[b] - s[a]) / 1000.0
prefill = s.get("prefill_token_per_sec") or s["prompt_tokens"] / secs("inference_start_ms", "prompt_eval_end_ms")
decode = s.get("decode_token_per_sec") or s["generated_tokens"] / secs("prompt_eval_end_ms", "inference_end_ms")
rss = re.search(r"RSS after loading model: ([0-9.]+) MiB", text)
rss = f"{float(rss.group(1)):.0f}" if rss else "n/a"
print(f"| {threads} | {s['prompt_tokens']} | {s['generated_tokens']} | "
      f"{secs('model_load_start_ms', 'model_load_end_ms'):.1f} | {secs('inference_start_ms', 'first_token_ms'):.1f} | "
      f"{prefill:.2f} | {decode:.2f} | {rss} | {temp} | {thr} |")
PY
done
echo
echo "Throttled 0x0 means no under-voltage or thermal throttling. Raw logs: bench_threads_*.log"
