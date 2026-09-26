#!/usr/bin/env python3
"""Оракул НЕВЕРНОЙ КОМПИЛЯЦИИ: схема обязана отвергать то, что отвергает исходник.

Зачем отдельно от механизма единственности. Наш основной оракул ищет
недоограниченность — два свидетеля при одних и тех же зафиксированных входах.
Измерено (итерация 75): на трёх РЕАЛЬНЫХ ошибках соундности компилятора он не
срабатывает, и это не дефект реализации, а граница метода. У тех ошибок свидетель
единственный; схема просто вычисляет не то, что написано в исходном тексте, и
принимает витнесс, который исходник отвергает.

Здесь оракул другой: смысл исходного текста пересчитывается независимо на Python,
и проверяются ОБА направления.
    ожидается принятие -> схема обязана принять и выдать то же значение;
    ожидается отказ    -> схема обязана отказать.
Принятая программа, которую исходник отвергает, и есть неверная компиляция.

Формы взяты те, в которых жили все три реальные ошибки августа 2026:
  * цикл `while` и следующий за ним `for` с условием на той же переменной
    (#13481: LICM перенёс границы индукции на соседний цикл и свернул условие);
  * предицированное чтение массива на выбранной ветви
    (#13486: чтение разрешалось как отключённый доступ и привязывалось к нулю);
  * запись по динамическому индексу и доступ за границу
    (#13462: проверка границ не учитывала уплощённый размер).
"""
from __future__ import annotations
import argparse, pathlib, random, shutil, subprocess

def run(cmd, cwd=None, timeout=120):
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None

def shape_licm(rng):
    """while-цикл, затем for с условием на той же переменной индукции."""
    # Область срабатывания измерена (итерация 76): ошибка проявляется при
    # границе `while` не меньше двух и при совпадении границы условия с ней.
    #   while i<3, for 0..2, (i<3): истина 0, схема 20  <- ошибка
    #   while i<1, for 0..3, (i<1): истина 0, схема 0   <- нет
    # Смещаю сюда, но не жёстко: соседние значения оставлены, чтобы поиск не
    # свёлся к воспроизведению одной известной ошибки и мог найти другие.
    a = rng.randint(2, 6); c = rng.randint(1, 4); trigger = rng.randint(0, 9)
    d = rng.choices([a, a - 1, a + 1, rng.randint(1, 8)], weights=[6, 2, 2, 1])[0]
    x = rng.randint(0, 9)
    src = f"""unconstrained fn inner(x: u32) -> u32 {{
    let mut i: u32 = 0;
    let mut acc: u32 = 0;
    while i < {a} {{
        if x == {trigger} {{ acc += 1; }}
        i += 1;
    }}
    let mut total: u32 = 0;
    for _k in 0..{c} {{
        total += (i < {d}) as u32;
    }}
    total * 10 + acc
}}

fn main(x: u32) {{
    // Safety: чистое вычисление над x.
    let t = unsafe {{ inner(x) }};
    assert(t == {{CLAIM}});
}}"""
    i_after = a
    acc = c_acc = (a if x == trigger else 0)
    total = c * (1 if i_after < d else 0)
    truth = total * 10 + acc
    return src, {"x": x}, truth

def shape_predicated_read(rng):
    """Запись по динамическому индексу, затем чтение на выбранной ветви."""
    base = [rng.randint(1, 9) for _ in range(4)]
    idx = rng.randint(0, 3); val = rng.randint(10, 99); c = rng.choice([0, 1])
    read_at = rng.randint(0, 3)
    src = f"""fn main(idx: u32, c: bool, val: Field) -> pub Field {{
    let mut arr: [Field; 4] = [{", ".join(str(v) for v in base)}];
    arr[idx] = val;
    let mut out: Field = 0;
    if c {{
        out = arr[{(read_at + 1) % 4}];
    }} else {{
        out = arr[{read_at}];
    }}
    assert(out == {{CLAIM}});
    out
}}"""
    arr = list(base); arr[idx] = val
    truth = arr[(read_at + 1) % 4] if c else arr[read_at]
    return src, {"idx": idx, "c": bool(c), "val": val}, truth

def shape_nested_index(rng):
    """Двумерный доступ с динамическими индексами по обеим осям."""
    rows, cols = rng.randint(2, 4), rng.randint(2, 4)
    m = [[rng.randint(1, 9) for _ in range(cols)] for _ in range(rows)]
    i = rng.randint(0, rows - 1); j = rng.randint(0, cols - 1)
    body = ", ".join("[" + ", ".join(str(v) for v in row) + "]" for row in m)
    src = f"""fn main(i: u32, j: u32) -> pub u32 {{
    let m: [[u32; {cols}]; {rows}] = [{body}];
    let out = m[i][j];
    assert(out == {{CLAIM}});
    out
}}"""
    return src, {"i": i, "j": j}, m[i][j]

def shape_nested_loops(rng):
    """Вложенные циклы: внутренняя граница зависит от внешнего счётчика."""
    n = rng.randint(2, 4); m = rng.randint(2, 4)
    src = f"""unconstrained fn inner(x: u32) -> u32 {{
    let mut acc: u32 = 0;
    let mut i: u32 = 0;
    while i < {n} {{
        let mut j: u32 = 0;
        while j < {m} {{
            if (j < i) {{ acc += 1; }}
            j += 1;
        }}
        i += 1;
    }}
    let mut tail: u32 = 0;
    for _k in 0..2 {{
        tail += (i < {n}) as u32 + (x < {n}) as u32;
    }}
    acc * 10 + tail
}}

fn main(x: u32) {{
    // Safety: чистое вычисление над x.
    let t = unsafe {{ inner(x) }};
    assert(t == {{CLAIM}});
}}"""
    x = rng.randint(0, 6)
    acc = sum(1 for i in range(n) for j in range(m) if j < i)
    tail = 2 * ((1 if n < n else 0) + (1 if x < n else 0))
    return src, {"x": x}, acc * 10 + tail


def shape_write_in_loop(rng):
    """Запись в массив по индексу, вычисляемому в цикле."""
    size = rng.randint(2, 4)
    base = [rng.randint(1, 9) for _ in range(size)]
    n = rng.randint(1, size)
    body = ", ".join(str(v) for v in base)
    src = f"""fn main(k: u32) -> pub u32 {{
    let mut arr: [u32; {size}] = [{body}];
    let mut i: u32 = 0;
    while i < {n} {{
        arr[i] = arr[i] + k;
        i += 1;
    }}
    let mut s: u32 = 0;
    for j in 0..{size} {{
        s = s + arr[j] * ((j < {n}) as u32 + 1);
    }}
    assert(s == {{CLAIM}});
    s
}}"""
    k = rng.randint(0, 5)
    arr = list(base)
    for i in range(n):
        arr[i] += k
    s = sum(arr[j] * ((1 if j < n else 0) + 1) for j in range(size))
    return src, {"k": k}, s


def shape_zero_width(rng):
    """Массив элементов НУЛЕВОЙ ширины плюс обычный рядом.

    На уплощённом размере при нулевой ширине элемента сидела ошибка #13462:
    проверка выхода за границы его не учитывала. Область малоисследованная,
    потому что нулевые размеры редко пишут руками.
    """
    outer = rng.randint(2, 4)
    idx = rng.randint(0, outer - 1)
    vals = [rng.randint(1, 9) for _ in range(outer)]
    body = ", ".join(str(v) for v in vals)
    src = f"""fn main(i: u32) -> pub u32 {{
    let mut empty: [[Field; 0]; {outer}] = [{", ".join("[]" for _ in range(outer))}];
    let real: [u32; {outer}] = [{body}];
    empty[i] = [];
    let out = real[i];
    assert(out == {{CLAIM}});
    out
}}"""
    return src, {"i": idx}, vals[idx]


def shape_branch_index(rng):
    """Динамический индекс, зависящий от ветви: обе ветви читают массив."""
    size = rng.randint(2, 4)
    vals = [rng.randint(1, 9) for _ in range(size)]
    a, b = rng.randint(0, size - 1), rng.randint(0, size - 1)
    c = rng.choice([0, 1])
    body = ", ".join(str(v) for v in vals)
    src = f"""fn main(c: bool, k: u32) -> pub u32 {{
    let arr: [u32; {size}] = [{body}];
    let idx = if c {{ {a} }} else {{ {b} }};
    let mut out = arr[idx];
    if c {{
        out = out + arr[{a}];
    }} else {{
        out = out + arr[{b}];
    }}
    let _ = k;
    assert(out == {{CLAIM}});
    out
}}"""
    k = rng.randint(0, 3)
    pick = a if c else b
    return src, {"c": bool(c), "k": k}, vals[pick] * 2


def shape_vector_dynamic(rng):
    """Вектор переменной длины: добавление в цикле, затем чтение и длина."""
    n = rng.randint(1, 4)
    base = rng.randint(1, 9)
    src = f"""fn main(x: u32) -> pub u32 {{
    let mut v = [].as_vector();
    let mut i: u32 = 0;
    while i < {n} {{
        v = v.push_back(x + i);
        i += 1;
    }}
    let mut s: u32 = 0;
    for j in 0..{n} {{
        s = s + v[j];
    }}
    s = s + (v.len() as u32) * ((i < {n}) as u32 + 1);
    assert(s == {{CLAIM}});
    s
}}"""
    x = base
    s = sum(x + i for i in range(n))
    s = s + n * (0 + 1)          # после цикла i == n, значит (i < n) ложно
    return src, {"x": x}, s


SHAPES = [shape_licm, shape_predicated_read, shape_nested_index,
          shape_nested_loops, shape_write_in_loop,
          shape_zero_width, shape_branch_index, shape_vector_dynamic]

def toml(vals):
    out = []
    for k, v in vals.items():
        out.append(f"{k} = {str(v).lower()}" if isinstance(v, bool) else f'{k} = "{v}"')
    return "\n".join(out) + "\n"

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cases", type=int, default=300)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--work", type=pathlib.Path, required=True)
    # Путь к компилятору задаётся явно. Смысл: установленный `nargo` может быть
    # старше известных исправлений, и тогда оракул будет повторять уже
    # исправленные ошибки. Против собранного из свежих исходников любая находка
    # является новой.
    ap.add_argument("--nargo", default="nargo")
    a = ap.parse_args()
    rng = random.Random(a.seed)
    pkg = a.work / "mf"
    st = {"проверено": 0, "НЕВЕРНАЯ КОМПИЛЯЦИЯ": 0, "ложный отказ": 0, "пропущено": 0,
          "испытан отказ": 0, "испытано принятие": 0}
    for case in range(a.cases):
        shape = rng.choice(SHAPES)
        try:
            src, vals, truth = shape(rng)
        except Exception:
            st["пропущено"] += 1; continue
        for label, claim in (("правда", truth), ("ложь", truth + rng.randint(1, 5))):
            shutil.rmtree(pkg, ignore_errors=True); (pkg / "src").mkdir(parents=True)
            (pkg / "Nargo.toml").write_text('[package]\nname = "mf"\ntype = "bin"\nauthors = [""]\n')
            (pkg / "src/main.nr").write_text(src.replace("{CLAIM}", str(claim)))
            (pkg / "Prover.toml").write_text(toml(vals))
            c = run([a.nargo, "compile", "--force", "--silence-warnings"], cwd=pkg)
            if c is None or c.returncode != 0:
                st["пропущено"] += 1; continue
            e = run([a.nargo, "execute", "--silence-warnings", "w"], cwd=pkg)
            if e is None:
                st["пропущено"] += 1; continue
            accepted = e.returncode == 0
            st["проверено"] += 1
            keep = a.work / f"case{case}_{label}"
            if label == "ложь":
                st["испытан отказ"] += 1
                if accepted:
                    st["НЕВЕРНАЯ КОМПИЛЯЦИЯ"] += 1
                    print(f"[НЕВЕРНАЯ КОМПИЛЯЦИЯ] {shape.__name__} вход={vals}", flush=True)
                    print(f"    исходник требует отказа (истина={truth}, заявлено={claim}), "
                          f"схема ПРИНЯЛА", flush=True)
                    shutil.rmtree(keep, ignore_errors=True); shutil.copytree(pkg, keep)
            else:
                st["испытано принятие"] += 1
                if not accepted:
                    st["ложный отказ"] += 1
                    print(f"[ЛОЖНЫЙ ОТКАЗ] {shape.__name__} вход={vals} истина={truth}, "
                          f"схема ОТКЛОНИЛА", flush=True)
                    shutil.rmtree(keep, ignore_errors=True); shutil.copytree(pkg, keep)
        if st["проверено"] % 20 == 0 and st["проверено"]:
            print(f"  ... {st}", flush=True)
    print(f"ИТОГ: {st}")

if __name__ == "__main__":
    main()
