#!/usr/bin/env python3
"""Сличение вычислителя времени компиляции с выполнением схемы.

Основание. В Noir есть `comptime`: отдельный интерпретатор, исполняющий код на
этапе компиляции. Это ВТОРОЙ вычислитель того же языка, и он обязан давать те же
результаты, что и выполнение схемы. Два независимых вычислителя одного языка —
пара, для которой оракул бесплатен: эталоном служат они друг другу.

Область малоисследованная. Собственный фаззер Noir порождает SSA и сравнивает
ACIR с Brillig; интерпретатор времени компиляции при этом не задействован вовсе.

Проверяются оба свойства:
  согласие значений — на одних и тех же константах оба пути дают одно число;
  согласие отказов  — переполнение, уход ниже нуля и деление на ноль обязаны
                      отвергаться обоими, а не тихо заворачиваться одним из них.
Второе важнее: тихо завёрнутая константа времени компиляции попадает в схему как
верная, и никакое выполнение этого уже не покажет.
"""
from __future__ import annotations
import argparse, pathlib, random, shutil, subprocess

LIMITS = {"u8": 255, "u16": 65535, "u32": 4294967295}

def run(cmd, cwd=None, timeout=120):
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None

class Bad(Exception):
    pass

def gen(rng, depth, ty):
    limit = LIMITS[ty]
    if depth == 0 or rng.random() < 0.35:
        if rng.random() < 0.6:
            v = rng.choice("ab")
            return v, (lambda e, v=v: e[v])
        k = rng.randint(0, min(limit, 200))
        return f"{k}", (lambda e, k=k: k)
    op = rng.choice(["+", "-", "*", "/", "%", "&", "|"])
    ls, lf = gen(rng, depth - 1, ty)
    rs, rf = gen(rng, depth - 1, ty)
    if op in ("/", "%"):
        k = rng.randint(1, min(limit, 100))
        rs, rf = f"{k}", (lambda e, k=k: k)
    text = f"({ls} {op} {rs})"

    def ev(e, op=op, lf=lf, rf=rf, limit=limit):
        x, y = lf(e), rf(e)
        if op == "+": r = x + y
        elif op == "-": r = x - y
        elif op == "*": r = x * y
        elif op == "/": r = x // y
        elif op == "%": r = x % y
        elif op == "&": r = x & y
        elif op == "|": r = x | y
        else: raise AssertionError(op)
        if r < 0 or r > limit:
            raise Bad()
        return r
    return text, ev

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cases", type=int, default=300)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--types", default="u8,u16,u32")
    ap.add_argument("--nargo", default="nargo")
    ap.add_argument("--work", type=pathlib.Path, required=True)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    pkg = a.work / "cd"
    st = {"сличено": 0, "РАСХОЖДЕНИЕ ЗНАЧЕНИЙ": 0, "РАСХОЖДЕНИЕ ОТКАЗОВ": 0,
          "пропущено": 0, "испытан отказ": 0, "испытано значение": 0}
    for case in range(a.cases):
        ty = rng.choice(a.types.split(","))
        limit = LIMITS[ty]
        text, ev = gen(rng, rng.randint(2, 4), ty)
        env = {k: rng.choice([0, 1, 2, limit - 1, limit, limit // 2])
               if rng.random() < 0.55 else rng.randint(0, limit) for k in "ab"}
        try:
            truth = ev(env); overflows = False
        except Bad:
            truth = None; overflows = True
        shutil.rmtree(pkg, ignore_errors=True); (pkg / "src").mkdir(parents=True)
        (pkg / "Nargo.toml").write_text('[package]\nname = "cd"\ntype = "bin"\nauthors = [""]\n')
        (pkg / "src/main.nr").write_text(
            f"fn compute(a: {ty}, b: {ty}) -> {ty} {{ {text} }}\n\n"
            f"fn main(x: {ty}, y: {ty}) -> pub ({ty}, {ty}) {{\n"
            f"    let at_runtime = compute(x, y);\n"
            f"    let at_comptime: {ty} = comptime {{ compute({env['a']}, {env['b']}) }};\n"
            f"    (at_runtime, at_comptime)\n}}\n")
        (pkg / "Prover.toml").write_text(f'x = "{env["a"]}"\ny = "{env["b"]}"\n')
        r = run([a.nargo, "execute", "--silence-warnings", "w"], cwd=pkg)
        if r is None:
            st["пропущено"] += 1; continue
        out = r.stdout + r.stderr
        accepted = r.returncode == 0
        st["сличено"] += 1
        keep = a.work / f"case{case}"
        if overflows:
            st["испытан отказ"] += 1
            if accepted:
                st["РАСХОЖДЕНИЕ ОТКАЗОВ"] += 1
                print(f"[РАСХОЖДЕНИЕ ОТКАЗОВ] {ty} {text} вход={env}", flush=True)
                print(f"    выражение выходит за пределы типа, но собралось и выполнилось:\n"
                      f"    {out.strip()[:200]}", flush=True)
                shutil.rmtree(keep, ignore_errors=True); shutil.copytree(pkg, keep)
        else:
            st["испытано значение"] += 1
            line = next((l for l in out.splitlines() if "Circuit output" in l), None)
            if not accepted:
                st["РАСХОЖДЕНИЕ ОТКАЗОВ"] += 1
                print(f"[ЛОЖНЫЙ ОТКАЗ] {ty} {text} вход={env} истина={truth}\n"
                      f"    {out.strip()[:200]}", flush=True)
                shutil.rmtree(keep, ignore_errors=True); shutil.copytree(pkg, keep)
            elif line is not None:
                # выход вида "Circuit output: (rt, ct)" — оба обязаны равняться истине
                nums = [n for n in line.replace("(", " ").replace(")", " ")
                        .replace(",", " ").split() if n.lstrip("-").isdigit()]
                if len(nums) >= 2 and not (int(nums[-2]) == truth == int(nums[-1])):
                    st["РАСХОЖДЕНИЕ ЗНАЧЕНИЙ"] += 1
                    print(f"[РАСХОЖДЕНИЕ ЗНАЧЕНИЙ] {ty} {text} вход={env}\n"
                          f"    истина={truth}, выполнение={nums[-2]}, "
                          f"время компиляции={nums[-1]}", flush=True)
                    shutil.rmtree(keep, ignore_errors=True); shutil.copytree(pkg, keep)
        if st["сличено"] % 25 == 0:
            print(f"  ... {st}", flush=True)
    print(f"ИТОГ: {st}")

if __name__ == "__main__":
    main()
