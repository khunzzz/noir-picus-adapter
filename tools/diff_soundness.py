#!/usr/bin/env python3
"""Дифференциальная проверка СОУНДНОСТИ между уровнями оптимизации.

Зачем это отдельный инструмент. Дифференциальный ЗАПУСК (tools/diff_exec.sh)
сравнивает результаты выполнения одной программы, собранной по-разному. Такой
метод не способен обнаружить потерю ограничения: если оптимизация выбросила
проверку, честный свидетель всё равно проходит на обоих уровнях и результаты
совпадают. Разница видна не в результате, а в МНОЖЕСТВЕ допустимых свидетелей.

Здесь сравнивается именно оно. Для каждой программы:
  1. сборка со всеми проходами и с отключением каждого из опасных проходов SSA;
  2. на каждой сборке — статический проход `unpinned` и поиск `mutate`;
  3. расхождение вердиктов между сборками = кандидат на ошибку компилятора.

Номера сигналов между сборками не совпадают, поэтому сравниваются только
величины, выразимые через интерфейс программы: число незакреплённых выходов
подсказок и факт нахождения второго свидетеля.

Для программ режима `pure` порог строже: подсказок в них нет, поэтому ЛЮБАЯ
находка на ЛЮБОМ уровне — ошибка компилятора, а не свойство схемы.
"""
from __future__ import annotations
import argparse, hashlib, json, pathlib, re, shutil, subprocess, sys, tempfile

ADAPTER = pathlib.Path(__file__).resolve().parent.parent / "target/release/noir-picus-adapter"
GEN = pathlib.Path(__file__).resolve().parent / "noir_gen.py"
MKTOML = pathlib.Path(__file__).resolve().parent / "make_prover_toml.py"
# Ось сравнения — отключение отдельных проходов SSA через скрытый флаг
# `--skip-ssa-pass` (compiler/noirc_driver/src/lib.rs, `#[arg(long, hide = true)]`).
#
# Прежняя ось `--inliner-aggressiveness` оказалась негодной: измерение показало,
# что артефакт на всех её значениях побайтово одинаков, то есть сравнивать было
# нечего. Здесь отключение прохода меняет артефакт, что проверено сверкой sha256.
#
# Отобраны проходы, способные УДАЛЯТЬ проверки, — только их ошибка даёт потерю
# ограничения. Пустая строка означает сборку со всеми проходами, то есть эталон.
PASSES = [
    "",
    "Checked to unchecked",
    "Dead Instruction Elimination",
    "Removing Truncate after RangeCheck",
    "Remove Unreachable Instructions",
    "EnableSideEffectsIf removal",
    "Simplifying",
    "Loop Invariant Code Motion",
    "Remove IfElse",
]


def pass_args(name: str) -> list:
    return ["--skip-ssa-pass", name] if name else []

def run(cmd, cwd=None, timeout=180):
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None

def probe(pkg: pathlib.Path, skip_pass: str, attempts: int, fast: bool = False):
    """Собрать при заданном уровне и вернуть вердикт, либо None если сборка не удалась."""
    # Prover.toml лежит в корне пакета и переживает очистку target — это и есть
    # закреплённый общий вход
    for p in pkg.glob("target/*"):
        p.unlink() if p.is_file() else shutil.rmtree(p, ignore_errors=True)
    r = run(["nargo", "compile", "--force", "--silence-warnings"]
            + pass_args(skip_pass), cwd=pkg)
    if r is None or r.returncode != 0:
        return None
    art = next(iter(pkg.glob("target/*.json")), None)
    if art is None:
        return None
    r = run(["nargo", "execute", "--silence-warnings", "w"]
            + pass_args(skip_pass), cwd=pkg)
    wit = pkg / "target/w.gz"
    if r is None or r.returncode != 0 or not wit.exists():
        return None
    u = run([str(ADAPTER), "unpinned", str(art)])
    n_unpinned = None
    if u and u.returncode == 0:
        m0 = re.search(r"(\d+) candidate", u.stdout)
        if m0:
            n_unpinned = int(m0.group(1))
    digest = hashlib.sha256(art.read_bytes()).hexdigest()[:16]
    if fast:
        # Двухступенчатая схема. Дорогой поиск `mutate` на порядок медленнее
        # статического прохода, а компиляция на пяти уровнях и без него стоит
        # десятки секунд. Поэтому первая ступень сравнивает только `unpinned`:
        # она дешёвая и полностью определённая, без случайности поиска. Вторая
        # ступень запускается лишь там, где первая показала разницу.
        return {"unpinned": n_unpinned, "found": None, "hints": None, "digest": digest}
    m = run([str(ADAPTER), "mutate", str(art), "--witness", str(wit),
             "--attempts", str(attempts), "--format", "json"], timeout=300)
    found = None
    hints = None
    if m and m.returncode == 0:
        try:
            d = json.loads(m.stdout)
            found = len(d.get("findings", []))
            hints = d.get("funnel", {}).get("hints")
        except Exception:
            pass
    return {"unpinned": n_unpinned, "found": found, "hints": hints, "digest": digest}

def find_input(pkg: pathlib.Path, tries: int = 24) -> bool:
    """Подобрать вход, который программа принимает, и закрепить его в Prover.toml.

    Первая версия стенда брала фиксированное зерно и сдавалась, если вход не
    прошёл внутренние проверки программы. На выборке из 250 это дало 77%
    пропусков: генератор ставит в программу assert-ы, а случайные значения им
    редко удовлетворяют. Пропуск здесь — не свойство компилятора, а потеря
    выборки, поэтому зёрна перебираются.

    Найденный Prover.toml потом НЕ пересоздаётся для других уровней оптимизации:
    все сборки обязаны получить один и тот же честный вход, иначе их вердикты
    несопоставимы. ABI от уровня встраивания не зависит, так что один файл подходит всем.
    """
    art = next(iter(pkg.glob("target/*.json")), None)
    if art is None:
        return False
    for seed in range(1, tries + 1):
        t = run([sys.executable, str(MKTOML), str(pkg), "--artifact", str(art), "--seed", str(seed)])
        if t is None or t.returncode != 0:
            continue
        r = run(["nargo", "execute", "--silence-warnings", "w"], cwd=pkg)
        if r is not None and r.returncode == 0:
            return True
    return False


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seeds", type=int, default=50)
    ap.add_argument("--start", type=int, default=0)
    ap.add_argument("--mode", default="pure")
    ap.add_argument("--size", type=int, default=10)
    ap.add_argument("--attempts", type=int, default=4)
    ap.add_argument("--work", type=pathlib.Path, required=True)
    ap.add_argument("--fast", action="store_true",
                    help="только статический проход по всем уровням (первая ступень)")
    a = ap.parse_args()
    a.work.mkdir(parents=True, exist_ok=True)
    stats = {"built": 0, "skipped": 0, "no_signal": 0, "divergent": 0,
             "опасных": 0, "finding_any": 0}
    for seed in range(a.start, a.start + a.seeds):
        pkg = a.work / f"p{seed}"
        shutil.rmtree(pkg, ignore_errors=True)
        g = run([sys.executable, str(GEN), "--seed", str(seed), "--mode", a.mode,
                 "--size", str(a.size), "--out", str(pkg)])
        if g is None or g.returncode != 0 or not (pkg / "Nargo.toml").exists():
            stats["skipped"] += 1; continue
        # сборка по умолчанию + подбор принимаемого входа, до сравнения уровней
        b = run(["nargo", "compile", "--force", "--silence-warnings"], cwd=pkg)
        if b is None or b.returncode != 0 or not find_input(pkg):
            stats["skipped"] += 1; shutil.rmtree(pkg, ignore_errors=True); continue
        verdicts = {}
        for inl in PASSES:
            v = probe(pkg, inl, a.attempts, fast=a.fast)
            if v is None:
                verdicts = {}; break
            verdicts[inl] = v
        if not verdicts:
            stats["skipped"] += 1; shutil.rmtree(pkg, ignore_errors=True); continue
        # Защита от пустого сравнения. Уровень встраивания управляет ТОЛЬКО
        # Brillig-функциями. В программе без подсказок Brillig нет, поэтому все
        # пять сборок дают побайтово одинаковый ACIR, и «ноль расхождений»
        # не говорит об оптимизаторе ничего. Проверено измерением: на чистой
        # программе sha256 артефакта совпал на всех трёх крайних уровнях
        # встраивания — из-за чего прежняя ось и была заменена.
        # Такие программы не результат, а отсутствие опыта — считаются отдельно.
        if len({v["digest"] for v in verdicts.values()}) == 1:
            stats["no_signal"] += 1
            shutil.rmtree(pkg, ignore_errors=True)
            continue
        stats["built"] += 1
        us = {v["unpinned"] for v in verdicts.values()}
        fs = {v["found"] for v in verdicts.values()}
        hs = {v["hints"] for v in verdicts.values()}
        any_found = any((v["found"] or 0) > 0 for v in verdicts.values())
        if a.fast:
            fs = {None}
        if any_found:
            stats["finding_any"] += 1
            print(f"[НАХОДКА] seed={seed} mode={a.mode} -> {verdicts}", flush=True)
        if len(us) > 1 or len(fs) > 1:
            # НАПРАВЛЕНИЕ расхождения решает всё, и его надо разделять.
            #
            # Ошибка оптимизатора выглядит так: полностью оптимизированная сборка
            # помечена, а сборка с ОТКЛЮЧЁННЫМ проходом чиста — значит проход
            # что-то убрал. Обратное направление (помечена неоптимизированная)
            # для соундности безопасно: там оптимизация ничего не теряла, просто
            # наш анализ хуже справился с более многословной схемой.
            #
            # Измерено на двух первых расхождениях: seed=9142 было опасного
            # направления и оказалось потерей точности анализа (исправлено),
            # seed=9438 — безопасного, и упирается в нераспознанный гаджет
            # каноничности приведения `Field` к целому.
            baseline = verdicts.get("", {}).get("unpinned")
            flagged_when_optimized = baseline is not None and baseline > 0
            direction = ("ОПАСНОЕ: помечена оптимизированная сборка"
                         if flagged_when_optimized
                         else "безопасное: помечена сборка с отключённым проходом")
            stats["divergent"] += 1
            if flagged_when_optimized:
                stats["опасных"] = stats.get("опасных", 0) + 1
            print(f"             направление — {direction}", flush=True)
            print(f"[РАСХОЖДЕНИЕ] seed={seed} unpinned={us} found={fs} hints={hs}", flush=True)
            print(f"             пакет сохранён: {pkg}", flush=True)
            continue
        shutil.rmtree(pkg, ignore_errors=True)
        if stats["built"] % 10 == 0:
            print(f"  ... собрано {stats['built']}, расхождений {stats['divergent']}", flush=True)
    print(f"ИТОГ: {stats}")

if __name__ == "__main__":
    main()
