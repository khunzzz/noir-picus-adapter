#!/usr/bin/env python3
"""Сличение двух версий компилятора: они служат эталоном друг другу.

Зачем. Оракул `mustfail_fuzz.py` требует, чтобы смысл программы можно было
пересчитать на Python, поэтому набор его форм узок и написан руками. Здесь
эталон не нужен вовсе: одна и та же программа собирается ДВУМЯ компиляторами и
выполняется на одном входе. Если вердикты или значения расходятся, ровно одна из
версий неправа.

Различать два случая обязательно:
  старая ошибается, новая права -> уже исправленная ошибка, находкой не является;
  новая ошибается, старая права -> РЕГРЕССИЯ, внесённая свежими правками.

Второй случай и есть цель: это ошибка, которой ещё нет в известных.

Программы берутся у нашего же генератора `noir_gen.py`, поэтому формы шире
рукописных: он покрывает арифметику, приведения, массивы, ветвления и подсказки.
"""
from __future__ import annotations
import argparse, pathlib, shutil, subprocess, sys

GEN = pathlib.Path(__file__).resolve().parent / "noir_gen.py"
MKTOML = pathlib.Path(__file__).resolve().parent / "make_prover_toml.py"

def run(cmd, cwd=None, timeout=150):
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None

def outcome(nargo, pkg):
    """Вердикт и выход одного компилятора: ('ok', значение) либо ('reject', причина)."""
    for p in pkg.glob("target/*"):
        p.unlink() if p.is_file() else shutil.rmtree(p, ignore_errors=True)
    c = run([nargo, "compile", "--force", "--silence-warnings"], cwd=pkg)
    if c is None or c.returncode != 0:
        return ("build", "")
    e = run([nargo, "execute", "--silence-warnings", "w"], cwd=pkg)
    if e is None:
        return ("timeout", "")
    text = e.stdout + e.stderr
    if e.returncode != 0:
        return ("reject", "")
    line = next((l for l in text.splitlines() if "Circuit output" in l), "")
    return ("ok", line.split(":", 1)[1].strip() if ":" in line else "")

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seeds", type=int, default=300)
    ap.add_argument("--start", type=int, default=0)
    ap.add_argument("--mode", default="hints")
    ap.add_argument("--size", type=int, default=12)
    ap.add_argument("--old", required=True, help="путь к старому nargo")
    ap.add_argument("--new", required=True, help="путь к новому nargo")
    ap.add_argument("--work", type=pathlib.Path, required=True)
    a = ap.parse_args()
    a.work.mkdir(parents=True, exist_ok=True)
    st = {"сличено": 0, "РАСХОЖДЕНИЙ": 0, "пропущено": 0}
    for seed in range(a.start, a.start + a.seeds):
        pkg = a.work / f"p{seed}"
        shutil.rmtree(pkg, ignore_errors=True)
        g = run([sys.executable, str(GEN), "--seed", str(seed), "--mode", a.mode,
                 "--size", str(a.size), "--out", str(pkg)])
        if g is None or g.returncode != 0 or not (pkg / "Nargo.toml").exists():
            st["пропущено"] += 1; continue
        # вход подбирается СТАРЫМ компилятором и затем используется обоими:
        # сравнивать вердикты на разных входах бессмысленно
        built = run([a.old, "compile", "--force", "--silence-warnings"], cwd=pkg)
        art = next(iter(pkg.glob("target/*.json")), None)
        if built is None or built.returncode != 0 or art is None:
            st["пропущено"] += 1; shutil.rmtree(pkg, ignore_errors=True); continue
        ok = False
        for s in range(1, 12):
            t = run([sys.executable, str(MKTOML), str(pkg), "--artifact", str(art), "--seed", str(s)])
            if t is None or t.returncode != 0:
                continue
            r = run([a.old, "execute", "--silence-warnings", "w"], cwd=pkg)
            if r is not None and r.returncode == 0:
                ok = True; break
        if not ok:
            st["пропущено"] += 1; shutil.rmtree(pkg, ignore_errors=True); continue

        old_v = outcome(a.old, pkg)
        new_v = outcome(a.new, pkg)
        if old_v[0] in ("build", "timeout") or new_v[0] in ("build", "timeout"):
            st["пропущено"] += 1; shutil.rmtree(pkg, ignore_errors=True); continue
        st["сличено"] += 1
        if old_v != new_v:
            st["РАСХОЖДЕНИЙ"] += 1
            print(f"[РАСХОЖДЕНИЕ] seed={seed}", flush=True)
            print(f"    старый: {old_v}", flush=True)
            print(f"    новый:  {new_v}", flush=True)
            print(f"    пакет сохранён: {pkg}", flush=True)
            continue
        shutil.rmtree(pkg, ignore_errors=True)
        if st["сличено"] % 20 == 0:
            print(f"  ... {st}", flush=True)
    print(f"ИТОГ: {st}")

if __name__ == "__main__":
    main()
