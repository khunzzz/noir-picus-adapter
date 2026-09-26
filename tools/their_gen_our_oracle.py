#!/usr/bin/env python3
"""Их генератор программ — наш оракул единственности.

Замысел. Наш собственный генератор (`noir_gen.py`) порождает программы узкого
вида: мы писали его руками и заложили в него те формы, которые сами придумали.
Генератор AST-фаззера Noir несравнимо богаче — вложенные сопоставления с
образцом, циклы `loop`/`while` с управлением, замыкания, векторы, глобальные
значения, рекурсия, разнородные типы. Такие формы мы построить не можем.

Здесь эти две сильные стороны соединяются: программы порождает ИХ генератор,
а недоограниченность ищет НАШ механизм. Проверяется то, ради чего работа и
делалась, но на самой богатой доступной выборке программ.

Отличие от прежнего конвейера по SSA-фаззеру (итерации ~50): тот работал на
уровне SSA, а этот — на уровне ИСХОДНОГО ТЕКСТА с подсказками, то есть ближе к
тому, как пишут люди.
"""
from __future__ import annotations
import argparse, pathlib, shutil, subprocess, sys

SAMPLE = "/home/said/noirsrc/target/release/examples/sample"
ADAPTER = pathlib.Path(__file__).resolve().parent.parent / "target/release/noir-picus-adapter"
MKTOML = pathlib.Path(__file__).resolve().parent / "make_prover_toml.py"

def run(cmd, cwd=None, timeout=180, out=None):
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=(out is None),
                              stdout=out, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rounds", type=int, default=200)
    ap.add_argument("--nargo", default="/home/said/noirsrc/target/release/nargo")
    ap.add_argument("--attempts", type=int, default=6)
    ap.add_argument("--work", type=pathlib.Path, required=True)
    a = ap.parse_args()
    a.work.mkdir(parents=True, exist_ok=True)
    st = {"порождено": 0, "собрано": 0, "прогнано": 0, "НАХОДОК": 0,
          "не собралось": 0, "нет свидетеля": 0, "подсказок всего": 0}
    for r in range(a.rounds):
        pkg = a.work / f"g{r}"
        shutil.rmtree(pkg, ignore_errors=True); (pkg / "src").mkdir(parents=True)
        (pkg / "Nargo.toml").write_text('[package]\nname = "g"\ntype = "bin"\nauthors = [""]\n')
        with open(pkg / "src/main.nr", "w") as f:
            g = run([SAMPLE], out=f, timeout=60)
        if g is None or g.returncode != 0:
            st["не собралось"] += 1; shutil.rmtree(pkg, ignore_errors=True); continue
        st["порождено"] += 1
        c = run([a.nargo, "compile", "--force", "--silence-warnings"], cwd=pkg)
        art = next(iter(pkg.glob("target/*.json")), None)
        if c is None or c.returncode != 0 or art is None:
            st["не собралось"] += 1; shutil.rmtree(pkg, ignore_errors=True); continue
        st["собрано"] += 1
        ok = False
        for seed in range(1, 10):
            t = run([sys.executable, str(MKTOML), str(pkg), "--artifact", str(art), "--seed", str(seed)])
            if t is None or t.returncode != 0:
                continue
            e = run([a.nargo, "execute", "--silence-warnings", "w"], cwd=pkg)
            if e is not None and e.returncode == 0:
                ok = True; break
        wit = pkg / "target/w.gz"
        if not ok or not wit.exists():
            st["нет свидетеля"] += 1; shutil.rmtree(pkg, ignore_errors=True); continue
        m = run([str(ADAPTER), "mutate", str(art), "--witness", str(wit),
                 "--attempts", str(a.attempts), "--format", "json"], timeout=240)
        if m is None or m.returncode != 0:
            st["нет свидетеля"] += 1; shutil.rmtree(pkg, ignore_errors=True); continue
        try:
            import json
            d = json.loads(m.stdout)
        except Exception:
            shutil.rmtree(pkg, ignore_errors=True); continue
        st["прогнано"] += 1
        st["подсказок всего"] += d.get("funnel", {}).get("hints", 0)
        found = len(d.get("findings", []))
        if found:
            st["НАХОДОК"] += found
            print(f"[НАХОДКА] раунд={r}, целей {found}", flush=True)
            for x in d["findings"][:2]:
                print(f"    {x}", flush=True)
            print(f"    пакет сохранён: {pkg}", flush=True)
            continue
        shutil.rmtree(pkg, ignore_errors=True)
        if st["прогнано"] % 10 == 0:
            print(f"  ... {st}", flush=True)
    print(f"ИТОГ: {st}")

if __name__ == "__main__":
    main()
