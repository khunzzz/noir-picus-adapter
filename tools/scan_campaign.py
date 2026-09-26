#!/usr/bin/env python3
"""Кампания на решателе: `scan` по сгенерированным программам с подсказками.

Зачем отдельно от `mutate_campaign`. Поиск `mutate` отталкивается от ЧЕСТНОГО
свидетеля и двигает выходы подсказок. У этого есть принципиальный предел,
измеренный в итерации 69: если дыра достижима только там, где честная подсказка
ПАДАЕТ, честного свидетеля не существует и двигаться не от чего. Наш эталонный
пример ровно таков — делительный гаджет `assert(q * b == a)` недоограничен при
a = b = 0, где `0 = 0*q` выполняется для любого q, а подсказка `0/0` при
выполнении падает.

`scan` этим не связан: он формулирует запрос единственности решателю и находит
пару свидетелей сам, без честной отправной точки. Поэтому он строго сильнее там,
где дыра сидит на входах, недостижимых честным путём, — а это как раз самый
опасный вид дыр, потому что обычное тестирование их не проявляет.

Плата — скорость: SMT-запрос на цель против перебора значений. Отсюда меньшие
объёмы и таймаут на программу.
"""
from __future__ import annotations
import argparse, json, pathlib, shutil, subprocess, sys

ADAPTER = pathlib.Path(__file__).resolve().parent.parent / "target/release/noir-picus-adapter"
GEN = pathlib.Path(__file__).resolve().parent / "noir_gen.py"

def run(cmd, cwd=None, timeout=300):
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seeds", type=int, default=200)
    ap.add_argument("--start", type=int, default=0)
    ap.add_argument("--mode", default="hints")
    ap.add_argument("--size", type=int, default=10)
    ap.add_argument("--timeout", type=int, default=240, help="таймаут на программу, с")
    ap.add_argument("--target-timeout", type=int, default=4000,
                    help="таймаут SMT-запроса на цель, мс")
    ap.add_argument("--work", type=pathlib.Path, required=True)
    a = ap.parse_args()
    a.work.mkdir(parents=True, exist_ok=True)
    st = {"разобрано": 0, "проверено целей": 0, "НЕБЕЗОПАСНЫХ": 0,
          "неизвестно": 0, "неподдержано": 0, "пропущено": 0, "таймаут": 0}
    for seed in range(a.start, a.start + a.seeds):
        pkg = a.work / f"p{seed}"
        shutil.rmtree(pkg, ignore_errors=True)
        g = run([sys.executable, str(GEN), "--seed", str(seed), "--mode", a.mode,
                 "--size", str(a.size), "--out", str(pkg)])
        if g is None or g.returncode != 0 or not (pkg / "Nargo.toml").exists():
            st["пропущено"] += 1; continue
        c = run(["nargo", "compile", "--force", "--silence-warnings"], cwd=pkg)
        art = next(iter(pkg.glob("target/*.json")), None)
        if c is None or c.returncode != 0 or art is None:
            st["пропущено"] += 1; shutil.rmtree(pkg, ignore_errors=True); continue
        # Цели сужены до выходов подсказок: именно там живёт искомый класс дыр,
        # а число запросов к решателю падает в разы. Ограничение времени на цель
        # не даёт одной трудной цели утянуть за собой всю программу — остальные
        # вердикты сохраняются.
        r = run([str(ADAPTER), "scan", str(art), "--format", "json",
                 "--targets", "brillig-outputs", "--timeout", str(a.target_timeout)],
                timeout=a.timeout)
        if r is None:
            st["таймаут"] += 1; shutil.rmtree(pkg, ignore_errors=True); continue
        try:
            data = json.loads(r.stdout)
        except Exception:
            st["пропущено"] += 1; shutil.rmtree(pkg, ignore_errors=True); continue
        st["разобрано"] += 1
        unsafe_here = []
        for prog in data.get("programs", []):
            for circ in prog.get("circuits", []):
                for tgt in circ.get("targets", []):
                    st["проверено целей"] += 1
                    status = tgt.get("status")
                    if status == "unsafe":
                        st["НЕБЕЗОПАСНЫХ"] += 1
                        unsafe_here.append((circ.get("name"), tgt))
                    elif status == "unknown":
                        st["неизвестно"] += 1
                    elif status == "unsupported":
                        st["неподдержано"] += 1
        if unsafe_here:
            print(f"[НЕБЕЗОПАСНО] seed={seed} режим={a.mode}", flush=True)
            for name, tgt in unsafe_here[:3]:
                print(f"    схема {name}, сигнал {tgt.get('witness')}: "
                      f"{tgt.get('reason','')[:160]}", flush=True)
            print(f"    пакет сохранён: {pkg}", flush=True)
            continue
        shutil.rmtree(pkg, ignore_errors=True)
        if st["разобрано"] % 10 == 0:
            print(f"  ... {st}", flush=True)
    print(f"ИТОГ: {st}")

if __name__ == "__main__":
    main()
