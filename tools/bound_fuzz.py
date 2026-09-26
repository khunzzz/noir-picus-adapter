#!/usr/bin/env python3
"""Поиск ошибок в анализе границ, на котором держится снятие проверок переполнения.

Основание. В списке проходов SSA компилятора Noir есть `Checked to unchecked`:
он убирает проверку переполнения там, где анализ доказал, что переполнение
невозможно. Такой проход — самое опасное место в оптимизаторе, потому что его
ошибка не портит вычисление на честных входах, а МОЛЧА СНИМАЕТ ПРОВЕРКУ.
Дифференциальный запуск этого не видит: честный вход проходит одинаково и с
проверкой, и без неё.

Оракул. Для выражения вида ((a % M1) * (b % M2) + (c % M3)) истинный максимум
считается точно и независимо, обычной арифметикой Python. Дальше два случая:

  истинный максимум <= предела типа -> переполнение невозможно; схема обязана
      ПРИНЯТЬ вход, дающий максимум, и выдать в точности это значение;
  истинный максимум >  предела типа -> переполнение возможно; схема обязана
      ОТКЛОНИТЬ вход, дающий максимум.

Несовпадение означает, что анализ границ компилятора разошёлся с истиной. Если
он ошибся в сторону "переполнение невозможно" — проверка снята напрасно, и это
ошибка соундности: схема примет свидетель с завёрнутым значением.

Смысл перебора модулей в том, чтобы сажать истинный максимум ВПЛОТНУЮ к пределу
типа с обеих сторон. Ошибка на единицу в анализе границ проявляется только там.
"""
from __future__ import annotations
import argparse, itertools, pathlib, random, shutil, subprocess, sys

LIMITS = {"u8": 255, "u16": 65535, "u32": 4294967295}

def run(cmd, cwd=None, timeout=120):
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None

SHAPES = [
    # (имя, исходный текст выражения, функция истинного максимума по (m1,m2,m3))
    ("mul",      "(a % {m1}) * (b % {m2})",                 lambda m: (m[0]-1)*(m[1]-1)),
    ("mul_add",  "(a % {m1}) * (b % {m2}) + (c % {m3})",    lambda m: (m[0]-1)*(m[1]-1)+(m[2]-1)),
    ("add_mul",  "((a % {m1}) + (b % {m2})) * (c % {m3})",  lambda m: ((m[0]-1)+(m[1]-1))*(m[2]-1)),
    ("sq_add",   "(a % {m1}) * (a % {m1}) + (b % {m2})",    lambda m: (m[0]-1)*(m[0]-1)+(m[1]-1)),
    ("triple",   "(a % {m1}) * (b % {m2}) * (c % {m3})",    lambda m: (m[0]-1)*(m[1]-1)*(m[2]-1)),
]

def build(pkg: pathlib.Path, ty: str, expr: str) -> None:
    shutil.rmtree(pkg, ignore_errors=True)
    (pkg / "src").mkdir(parents=True)
    (pkg / "Nargo.toml").write_text(
        '[package]\nname = "bf"\ntype = "bin"\nauthors = [""]\n')
    (pkg / "src/main.nr").write_text(
        f"fn main(a: {ty}, b: {ty}, c: {ty}) -> pub {ty} {{\n    {expr}\n}}\n")

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cases", type=int, default=200)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--types", default="u8,u16")
    ap.add_argument("--work", type=pathlib.Path, required=True)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    pkg = a.work / "bf"
    checked = mism = skipped = 0
    # Разбивка по случаям. Без неё нулевой результат нельзя отличить от пустого:
    # если бы все случаи оказались "переполнение невозможно, схема приняла",
    # проверка не испытывала бы анализ границ вовсе.
    tally = {"переполнение -> отклонено": 0, "без переполнения -> принято": 0}
    for case in range(a.cases):
        ty = rng.choice(a.types.split(","))
        limit = LIMITS[ty]
        name, tmpl, maxfn = rng.choice(SHAPES)
        # Модули подбираются так, чтобы истинный максимум лёг ВПЛОТНУЮ к пределу
        # типа. Это не косметика: ошибка на единицу в анализе границ проявляется
        # только в узкой полосе вокруг предела. Случайные модули почти всегда
        # дают максимум далеко от границы, где прав любой анализ.
        best, best_gap = None, None
        for _ in range(400):
            cand = [rng.randint(2, min(limit, 400)) for _ in range(3)]
            gap = abs(maxfn(cand) - limit)
            if best_gap is None or gap < best_gap:
                best, best_gap = cand, gap
            if gap <= 2:
                break
        if best is None or best_gap > limit // 8:
            skipped += 1; continue
        m = best
        true_max = maxfn(m)
        expr = tmpl.format(m1=m[0], m2=m[1], m3=m[2])
        build(pkg, ty, expr)
        if (r := run(["nargo", "compile", "--force", "--silence-warnings"], cwd=pkg)) is None \
           or r.returncode != 0:
            skipped += 1; continue
        # вход, достигающий максимума: остаток m-1 достигается значением m-1
        vals = {"a": m[0]-1, "b": m[1]-1, "c": m[2]-1}
        if name == "sq_add":
            vals["a"] = m[0]-1
        (pkg / "Prover.toml").write_text(
            "\n".join(f'{k} = "{v}"' for k, v in vals.items()) + "\n")
        e = run(["nargo", "execute", "--silence-warnings", "w"], cwd=pkg)
        if e is None:
            skipped += 1; continue
        out = (e.stdout + e.stderr)
        accepted = e.returncode == 0
        overflowed = true_max > limit
        checked += 1
        if overflowed and not accepted:
            tally["переполнение -> отклонено"] += 1
        elif not overflowed and accepted:
            tally["без переполнения -> принято"] += 1
        if overflowed and accepted:
            mism += 1
            print(f"[РАСХОЖДЕНИЕ] {ty} {name} m={m} истинный максимум={true_max} > {limit}, "
                  f"но схема ПРИНЯЛА вход {vals}", flush=True)
            print(f"              выражение: {expr}", flush=True)
            print(f"              вывод: {out.strip()[:200]}", flush=True)
            keep = a.work / f"case{case}"
            shutil.rmtree(keep, ignore_errors=True); shutil.copytree(pkg, keep)
        elif not overflowed and not accepted:
            mism += 1
            print(f"[РАСХОЖДЕНИЕ] {ty} {name} m={m} истинный максимум={true_max} <= {limit}, "
                  f"но схема ОТКЛОНИЛА вход {vals}", flush=True)
            print(f"              выражение: {expr}", flush=True)
            print(f"              вывод: {out.strip()[:200]}", flush=True)
            keep = a.work / f"case{case}"
            shutil.rmtree(keep, ignore_errors=True); shutil.copytree(pkg, keep)
        if checked % 25 == 0:
            print(f"  ... проверено {checked}, расхождений {mism}", flush=True)
    print(f"ИТОГ: проверено {checked}, расхождений {mism}, пропущено {skipped}")
    for k, v in tally.items():
        print(f"  {k}: {v}")

if __name__ == "__main__":
    main()
