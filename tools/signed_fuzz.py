#!/usr/bin/env python3
"""Поиск ошибок в знаковой целочисленной арифметике Noir.

Почему именно сюда. В списке проходов SSA под знаковые числа выделены ДВА
отдельных прохода: `expand signed checks` и `Expand signed math`. Отдельная
спецобработка — уже повод присмотреться, а знаковая арифметика в поле трудна
по существу: отрицательные числа представлены как элементы поля, и проверки
диапазона обязаны различать «большое положительное» и «отрицательное».

Особое внимание делению и остатку: они требуют явной возни со знаками, а деление
в поле не совпадает с целочисленным, поэтому реализуется через подсказку с
последующей проверкой. Это ровно та форма, где недоограниченность и возникает.

Семантика откалибрована измерением (см. журнал, итерация 69):
  `+`, `-`, `*`, `/`, `%` отказывают при выходе за диапазон типа;
  деление и остаток на ноль отказывают;
  MIN / -1 и MIN % -1 отказывают (как в Rust: деление переполняется);
  `>>` — арифметический сдвиг (знак сохраняется).
Неоткалиброванные операции (`<<`, `&`, `|` на знаковых) намеренно НЕ включены:
оракул с невыверенной семантикой производит ложные находки.
"""
from __future__ import annotations
import argparse, pathlib, random, shutil, subprocess

WIDTH = {"i8": 8, "i16": 16, "i32": 32}

def bounds(ty):
    w = WIDTH[ty]
    return -(1 << (w - 1)), (1 << (w - 1)) - 1

def run(cmd, cwd=None, timeout=120):
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None

class Bad(Exception):
    pass

def gen(rng, depth, ty):
    lo, hi = bounds(ty)
    if depth == 0 or rng.random() < 0.3:
        if rng.random() < 0.75:
            v = rng.choice("abc")
            return v, (lambda env, v=v: env[v])
        k = rng.randint(lo, hi)
        return (f"{k}" if k >= 0 else f"({k})"), (lambda env, k=k: k)
    op = rng.choice(["+", "-", "*", "/", "%", ">>"])
    ls, lf = gen(rng, depth - 1, ty)
    rs, rf = gen(rng, depth - 1, ty)
    if op == ">>":
        k = rng.randint(0, WIDTH[ty] - 1)
        rs, rf = f"{k}", (lambda env, k=k: k)
    text = f"({ls} {op} {rs})"

    def ev(env, op=op, lf=lf, rf=rf, lo=lo, hi=hi):
        x, y = lf(env), rf(env)
        if op == "+": r = x + y
        elif op == "-": r = x - y
        elif op == "*": r = x * y
        elif op == ">>": r = x >> y            # арифметический сдвиг
        elif op in ("/", "%"):
            if y == 0: raise Bad()
            if x == lo and y == -1: raise Bad()  # как в Rust
            q = abs(x) // abs(y)
            q = q if (x < 0) == (y < 0) else -q   # усечение к нулю
            r = q if op == "/" else x - q * y
        else: raise AssertionError(op)
        if r < lo or r > hi: raise Bad()
        return r
    return text, ev

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cases", type=int, default=300)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--types", default="i8,i16,i32")
    ap.add_argument("--samples", type=int, default=400)
    ap.add_argument("--work", type=pathlib.Path, required=True)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    pkg = a.work / "sf"
    st = {"проверено": 0, "снятая проверка": 0, "неверное значение": 0, "ложный отказ": 0,
          "пропущено": 0, "испытан отказ": 0, "испытано принятие": 0}
    for case in range(a.cases):
        ty = rng.choice(a.types.split(","))
        lo, hi = bounds(ty)
        text, ev = gen(rng, rng.randint(2, 4), ty)
        pool = [lo, lo + 1, -1, 0, 1, hi - 1, hi]
        envs = [{k: (rng.choice(pool) if rng.random() < 0.55 else rng.randint(lo, hi))
                 for k in "abc"} for _ in range(a.samples)]
        good = bad = None
        for env in envs:
            try:
                r = ev(env)
                if good is None: good = (env, r)
            except Bad:
                if bad is None: bad = env
            if good and bad: break
        if good is None and bad is None:
            st["пропущено"] += 1; continue
        shutil.rmtree(pkg, ignore_errors=True); (pkg / "src").mkdir(parents=True)
        (pkg / "Nargo.toml").write_text('[package]\nname = "sf"\ntype = "bin"\nauthors = [""]\n')
        (pkg / "src/main.nr").write_text(
            f"fn main(a: {ty}, b: {ty}, c: {ty}) -> pub {ty} {{\n    {text}\n}}\n")
        r = run(["nargo", "compile", "--force", "--silence-warnings"], cwd=pkg)
        if r is None or r.returncode != 0:
            st["пропущено"] += 1; continue
        st["проверено"] += 1
        for label, env, expect in (("bad", bad, None),
                                   ("good", good[0] if good else None, good[1] if good else None)):
            if env is None: continue
            (pkg / "Prover.toml").write_text(
                "\n".join(f'{k} = "{v}"' for k, v in env.items()) + "\n")
            e = run(["nargo", "execute", "--silence-warnings", "w"], cwd=pkg)
            if e is None: continue
            out = (e.stdout + e.stderr); accepted = e.returncode == 0
            keep = a.work / f"case{case}"
            if label == "bad":
                st["испытан отказ"] += 1
                if accepted:
                    st["снятая проверка"] += 1
                    print(f"[СНЯТАЯ ПРОВЕРКА] {ty}  {text}\n    вход {env} обязан быть отклонён, "
                          f"схема ПРИНЯЛА\n    вывод: {out.strip()[:200]}", flush=True)
                    shutil.rmtree(keep, ignore_errors=True); shutil.copytree(pkg, keep)
            else:
                st["испытано принятие"] += 1
                if not accepted:
                    st["ложный отказ"] += 1
                    print(f"[ЛОЖНЫЙ ОТКАЗ] {ty}  {text}\n    вход {env} корректен "
                          f"(истина={expect}), схема ОТКЛОНИЛА\n    вывод: {out.strip()[:200]}", flush=True)
                    shutil.rmtree(keep, ignore_errors=True); shutil.copytree(pkg, keep)
                else:
                    line = next((l for l in out.splitlines() if "Circuit output" in l), None)
                    if line and expect is not None and str(expect) not in line:
                        st["неверное значение"] += 1
                        print(f"[НЕВЕРНОЕ ЗНАЧЕНИЕ] {ty}  {text}\n    вход {env}: истина={expect}, "
                              f"схема: {line.strip()}", flush=True)
                        shutil.rmtree(keep, ignore_errors=True); shutil.copytree(pkg, keep)
        if st["проверено"] % 25 == 0:
            print(f"  ... {st}", flush=True)
    print(f"ИТОГ: {st}")

if __name__ == "__main__":
    main()
