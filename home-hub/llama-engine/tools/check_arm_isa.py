"""List ARM64 instructions that a Raspberry Pi 4 (Cortex-A72) cannot execute.

The Pi 4's CPU reports only: fp asimd evtstrm crc32 cpuid (Armv8.0-A). It has no
LSE atomics, no FP16 arithmetic, no dot-product, i8mm, BF16, SVE, RCPC or crypto
instructions. A binary that executes one of them stops with "Illegal instruction".

    python llama-engine/tools/check_arm_isa.py some_library.so another_binary

Needs llvm-objdump (sudo apt install llvm). Outline-atomic helpers that check
the CPU at run time before using LSE are recognised and not reported. Kernels
that libraries select at run time by CPU features (XNNPACK, KleidiAI) are
reported but are safe; what matters is unguarded code on paths you execute.
This is how we found why the ExecuTorch pip wheel crashes on the Pi 4
(../results/results_pi4.md).
"""
import re, subprocess, sys
from collections import Counter, defaultdict

LSE = re.compile(r"^(cas[ablhp]*|casp[al]*|ld(add|clr|eor|set|smax|smin|umax|umin)[al]*[bh]?|"
                 r"st(add|clr|eor|set|smax|smin|umax|umin)[l]*[bh]?|swp[al]*[bh]?)$")
CLASSES = [
    ("lse_atomics", lambda m, ops: bool(LSE.match(m))),
    ("rcpc", lambda m, ops: m.startswith(("ldapr", "ldapur"))),
    ("dotprod", lambda m, ops: m in ("sdot", "udot")),
    ("i8mm", lambda m, ops: m in ("smmla", "ummla", "usmmla", "usdot", "sudot")),
    ("bf16", lambda m, ops: m.startswith(("bfdot", "bfmmla", "bfmlal", "bfcvt"))),
    ("crypto", lambda m, ops: m.startswith(("aes", "sha1", "sha256", "sha512", "sm3", "sm4", "eor3", "bcax", "rax1", "xar"))
                              or (m in ("pmull", "pmull2") and ".1q" in ops)),
    ("fp16_arith", lambda m, ops: (m.startswith("f") and not m.startswith(("fcvt", "fmov"))
                                   and (re.search(r"\bh\d+\b", ops) or re.search(r"\.(4|8)h\b", ops)))),
    ("rdm", lambda m, ops: m in ("sqrdmlah", "sqrdmlsh")),
    ("sve", lambda m, ops: bool(re.search(r"\bz\d+\.", ops)) or m in ("ptrue", "whilelo", "whilelt", "ptest", "rdvl", "cntw", "cntb", "cntd", "cnth")),
    ("pauth_nonhint", lambda m, ops: m in ("retaa", "retab", "braa", "brab", "blraa", "blrab", "ldraa", "ldrab", "pacia", "pacib", "autia", "autib")),
    ("v8.3+_misc", lambda m, ops: m in ("fjcvtzs", "fcmla", "fcadd", "frint32x", "frint32z", "frint64x", "frint64z", "cfinv", "rmif", "setf8", "setf16")),
]
FUNC_RE = re.compile(r"^[0-9a-f]+ <(.+)>:$")
INS_RE = re.compile(r"^\s+[0-9a-f]+:\s+([a-z0-9.]+)\s*(.*)$")

for path in sys.argv[1:]:
    out = subprocess.run(["llvm-objdump", "-d", "--triple=aarch64-linux-gnu", "--mattr=+all",
                          "--no-show-raw-insn", "--demangle", path], capture_output=True, text=True).stdout
    counts, where = Counter(), defaultdict(Counter)
    func = "?"
    prev = []                       # last few instructions, to spot outline-atomic helpers
    guarded = 0
    for line in out.splitlines():
        fm = FUNC_RE.match(line)
        if fm:
            func = fm.group(1)
            continue
        im = INS_RE.match(line)
        if not im:
            continue
        mnem, ops = im.group(1), im.group(2)
        prev = (prev + [(mnem, ops)])[-4:]
        if LSE.match(mnem) and any(m == "cbz" and o.startswith("w16") for m, o in prev[:-1]):
            guarded += 1            # GCC/Clang outline-atomics helper: LSE only if the CPU has it
            continue
        for name, test in CLASSES:
            if test(mnem, ops):
                counts[name] += 1
                where[name][func] += 1
                break
    print(f"\n=== {path.split('/')[-1]}   (runtime-guarded LSE helpers skipped: {guarded})")
    if not counts:
        print("   clean: Armv8.0 only")
    for name, n in counts.most_common():
        funcs = where[name]
        outline = sum(v for f, v in funcs.items() if f.startswith("__aarch64_"))
        print(f"   {name:<14} {n:>7} instr in {len(funcs):>5} functions" + (f"  ({outline} in outline-atomic helpers)" if outline else ""))
        for f, v in funcs.most_common(4):
            print(f"        {v:>6}  {f[:200]}")
