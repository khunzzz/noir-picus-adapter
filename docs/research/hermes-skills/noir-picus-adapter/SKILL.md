---
name: noir-picus-adapter
description: "Scan Noir ACIR for under-constrained witness."
category: software-development
---

# Noir Picus Adapter

Инструмент поиска недоограниченности (under-constrained witnesses) в ACIR, который выдаёт Noir компилятор. Проект в `/home/said/noir-picus-adapter/`.

## Окружение

```bash
source /tmp/claude-1000/-home-said/2a6a48a6-cee3-4623-bac6-765c0631d66f/scratchpad/env.sh
```

| Что | Где |
|---|---|
| nargo | `$SP/noirbin26/nargo` или `$(which nargo)` |
| Адаптер | `./target/release/noir-picus-adapter` |
| Исходники Noir | `$SP/noirsrc` |

## Сборка и тесты

```bash
cargo build --release    # релизная сборка
cargo test               # 60 тестов
```

## Фикс памяти (2026-08-22)

В `src/mutate.rs`, `solve_pass()`, `MemOpKind::Write`: soft-хинты теперь берутся из honest вместо `deferred`. Без этого поиск не мог пройти через память с хинтовым значением.

## Сканирование корпуса

```bash
python3 tools/noir_testsuite_scan.py \
  --adapter ./target/release/noir-picus-adapter \
  --nargo "$(which nargo)" \
  --corpus "$SP/noirsrc/test_programs/compile_success_no_bug" \
  --work /tmp/noir_scan_work \
  --out /tmp/noir_scan_results.json \
  --attempts 6
```

## Что в findings/

- `non-pinning-constraint-silences-checker`
- `predicated-constraint-silences-checker`
- `array-output-length-threshold`
- `ancestor-distance-false-positive`
- `nightly-returndata-loop`
- `no-bug-corpus-underconstrained`

## Документация

- `ОТЧЁТ.md` — полный отчёт (русский, 943 строки)
- `RESEARCH_LOG.md` — журнал (2803 строки)
- `CLAUDE.md` — контекст Claude