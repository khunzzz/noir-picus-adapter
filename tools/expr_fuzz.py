#!/usr/bin/env python3
"""Проверка проверок: ищет снятые проверки переполнения и неверные значения.

Отличие от `bound_fuzz.py`. Там истинный максимум задавался формулой под каждую
форму выражения, поэтому набор форм был узким — только умножение с остатком.
Здесь выражение строится случайным деревом над a, b, c с операциями
`+ - * % & | >> <<` и приведением типов, а истина считается перебором входов на
обычной арифметике Python. Это позволяет испытывать те части анализа границ,
до которых формулами не дотянуться: вычитание (уход ниже нуля, а не
переполнение), сдвиги, побитовые маски и сужающие приведения.

Оракул на каждом входе, независимо от компилятора:
  если хоть одна промежуточная операция выходит за пределы типа (вверх или
      ниже нуля) -> схема ОБЯЗАНА отклонить вход;
  иначе -> схема ОБЯЗАНА принять его и выдать в точности вычисленное значение.

Отсюда две разные находки:
  принят вход, который обязан быть отклонён -> проверка СНЯТА (ошибка
      соундности: свидетель с завёрнутым значением пройдёт проверку);
  выдано значение, отличное от истинного -> неверная компиляция.
"""
from __future__ import annotations
import argparse, pathlib, random, shutil, subprocess

LIMITS = {"u8": 255, "u16": 65535, "u32": 4294967295}
BITS = {"u8": 8, "u16": 16, "u32": 32}

def run(cmd, cwd=None, timeout=120):
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None

class Overflow(Exception):
    pass

def gen(rng: random.Random, depth: int, ty: str):
    """Вернуть (текст на Noir, вычислитель). Вычислитель бросает Overflow при выходе за тип."""
    limit = LIMITS[ty]
    if depth == 0 or rng.random() < 0.3:
        if rng.random() < 0.75:
            v = rng.choice("abc")
            return v, (lambda env, v=v: env[v])
        k = rng.randint(0, min(limit, 255))
        return f"{k}", (lambda env, k=k: k)
    op = rng.choice(["+", "-", "*", "%", "&", "|", ">>", "<<"])
    ls, lf = gen(rng, depth - 1, ty)
    rs, rf = gen(rng, depth - 1, ty)
    if op in ("%",):
        # деление на ноль — отдельное поведение, здесь не изучается
        k = rng.randint(2, min(limit, 200))
        rs, rf = f"{k}", (lambda env, k=k: k)
    if op in (">>", "<<"):
        k = rng.randint(0, BITS[ty] - 1)
        rs, rf = f"{k}", (lambda env, k=k: k)
    text = f"({ls} {op} {rs})"

    def ev(env, op=op, lf=lf, rf=rf, limit=limit):
        x, y = lf(env), rf(env)
        if op == "+": r = x + y
        elif op == "-": r = x - y
        elif op == "*": r = x * y
        elif op == "%": r = x % y
        elif op == "&": r = x & y
        elif op == "|": r = x | y
        elif op == ">>": r = x >> y
        # Сдвиг влево в Noir УСЕКАЕТ, а не отказывает. Проверено опытом:
        # для u8 `254 << 1` даёт 252, то есть 508 mod 256, без ошибки — как в
        # Rust. Первая версия оракула считала это переполнением и немедленно
        # выдала ложную находку на `((b << 1) >> 5)`. Семантика каждой операции
        # откалибрована измерением: `+`, `-`, `*` отказывают при выходе за тип;
        # `<<` усекает; `>>`, `&`, `|` выйти за тип не могут.
        elif op == "<<": r = (x << y) & limit
        else: raise AssertionError(op)
        if r < 0 or r > limit:
            raise Overflow()
        return r
    return text, ev

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cases", type=int, default=300)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--types", default="u8,u16")
    ap.add_argument("--samples", type=int, default=400)
    ap.add_argument("--work", type=pathlib.Path, required=True)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    pkg = a.work / "ef"
    stats = {"проверено": 0, "снятая проверка": 0, "неверное значение": 0,
             "пропущено": 0, "испытан отказ": 0, "испытано принятие": 0}
    for case in range(a.cases):
        ty = rng.choice(a.types.split(","))
        limit = LIMITS[ty]
        text, ev = gen(rng, rng.randint(2, 4), ty)
        # входы: границы типа и случайные значения
        pool = [0, 1, 2, limit - 1, limit, limit // 2, limit // 2 + 1]
        cases_in = [{k: rng.choice(pool) if rng.random() < 0.5 else rng.randint(0, limit)
                     for k in "abc"} for _ in range(a.samples)]
        good, bad = None, None
        for env in cases_in:
            try:
                r = ev(env)
                if good is None: good = (env, r)
            except Overflow:
                if bad is None: bad = env
            if good and bad: break
        if good is None and bad is None:
            stats["пропущено"] += 1; continue
        shutil.rmtree(pkg, ignore_errors=True); (pkg / "src").mkdir(parents=True)
        (pkg / "Nargo.toml").write_text('[package]\nname = "ef"\ntype = "bin"\nauthors = [""]\n')
        (pkg / "src/main.nr").write_text(
            f"fn main(a: {ty}, b: {ty}, c: {ty}) -> pub {ty} {{\n    {text}\n}}\n")
        r = run(["nargo", "compile", "--force", "--silence-warnings"], cwd=pkg)
        if r is None or r.returncode != 0:
            stats["пропущено"] += 1; continue
        stats["проверено"] += 1
        for label, env, expect in (("bad", bad, None), ("good", good[0] if good else None,
                                                        good[1] if good else None)):
            if env is None: continue
            (pkg / "Prover.toml").write_text(
                "\n".join(f'{k} = "{v}"' for k, v in env.items()) + "\n")
            e = run(["nargo", "execute", "--silence-warnings", "w"], cwd=pkg)
            if e is None: continue
            out = (e.stdout + e.stderr)
            accepted = e.returncode == 0
            if label == "bad":
                stats["испытан отказ"] += 1
                if accepted:
                    stats["снятая проверка"] += 1
                    print(f"[СНЯТАЯ ПРОВЕРКА] {ty}  {text}", flush=True)
                    print(f"    вход {env} обязан переполниться, но схема ПРИНЯЛА его", flush=True)
                    print(f"    вывод: {out.strip()[:200]}", flush=True)
                    keep = a.work / f"case{case}"
                    shutil.rmtree(keep, ignore_errors=True); shutil.copytree(pkg, keep)
            else:
                stats["испытано принятие"] += 1
                if not accepted:
                    stats["неверное значение"] += 1
                    print(f"[ЛОЖНЫЙ ОТКАЗ] {ty}  {text}", flush=True)
                    print(f"    вход {env} корректен (истина={expect}), но схема ОТКЛОНИЛА", flush=True)
                    print(f"    вывод: {out.strip()[:200]}", flush=True)
                    keep = a.work / f"case{case}"
                    shutil.rmtree(keep, ignore_errors=True); shutil.copytree(pkg, keep)
                else:
                    got = None
                    for line in out.splitlines():
                        if "Circuit output" in line or "output" in line.lower():
                            got = line.strip()
                    if got and expect is not None:
                        hexv, decv = hex(expect), str(expect)
                        if hexv not in got.lower() and decv not in got:
                            stats["неверное значение"] += 1
                            print(f"[НЕВЕРНОЕ ЗНАЧЕНИЕ] {ty}  {text}", flush=True)
                            print(f"    вход {env}: истина={expect}, схема вернула: {got}", flush=True)
                            keep = a.work / f"case{case}"
                            shutil.rmtree(keep, ignore_errors=True); shutil.copytree(pkg, keep)
        if stats["проверено"] % 25 == 0:
            print(f"  ... {stats}", flush=True)
    print(f"ИТОГ: {stats}")

if __name__ == "__main__":
    main()
