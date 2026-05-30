# noir-picus-adapter

Проверка Noir ACIR-артефактов на недоограниченные значения.

Инструмент берет JSON, который выдает `nargo compile`, выбирает возвращаемые
значения и выходы `BrilligCall`, переводит поддержанные ограничения ACIR в Picus
SMT и проверяет, может ли один и тот же набор входов дать разные значения
целевого witness.

## Требования

- Rust 1.89+
- `git`, `bash`, `make`
- C/C++ toolchain
- `libclang` для `bindgen`

Зависимости на Noir и Picus закреплены в `Cargo.toml` по git revision. Локально
клонировать Noir или Picus не нужно.

Первый `cargo build` может быть долгим: Picus при необходимости собирает cvc5.

## Быстрый старт

```bash
cargo build

cargo run -- scan examples/artifacts/unsafe_division_hint \
  --targets returns \
  --fixed all-params
```

Путь к артефакту можно передавать с `.json` или без него.

## Команды

```bash
cargo run -- scan <artifact>
cargo run -- scan <artifact> --format json
cargo run -- scan <artifact> --dump-smt /tmp/noir-picus-smt
cargo run -- scan <artifact> --fixed public
cargo run -- scan <artifact> --targets returns
cargo run -- scan <artifact> --solver cvc5 --theory ff
cargo run -- scan <artifact> --verbose
```

`--verbose` добавляет детали по выбранным witness, числу Picus constraints,
источникам целей и SMT self-composition mapping (`x*` / `y*`). Обычно он нужен
для разбора конкретного результата, а не для обычного запуска.

По умолчанию:

- фиксируются все public/private параметры;
- проверяются возвращаемые witness и выходы `BrilligCall`;
- используется `cvc5` в finite-field режиме.

## Примеры

Готовые артефакты лежат в `examples/artifacts`, исходники Noir-примеров - в
`examples/*/src/main.nr`.

Ожидаемые результаты и дополнительные команды: [examples/README.md](examples/README.md).

## Корпус уязвимых цепей

Банк более реалистичных уязвимых цепей лежит в [corpus](corpus/README.md).
Он моделирует паттерны из Circom/R1CS/zkEVM-аудитов как Noir-артефакты для
массового запуска адаптера:

```bash
./target/debug/noir-picus-adapter scan corpus/artifacts/vuln_binary_merkle_selector \
  --fixed public \
  --targets returns
```

Для быстрой регрессии используется `bash corpus/check_corpus.sh`. Для
production-like оценки с medium/large схемами и fixed-вариантами используется
`bash corpus/check_realistic_corpus.sh`. Для PoC из GitHub Security Advisories
самого Noir-компилятора используется `bash corpus/check_compiler_regression.sh`;
это отдельный слой, потому что часть compiler bugs проверяется через
`nargo execute`, а не через uniqueness scan.

Навигация по corpus-документации описана в начале [corpus/README.md](corpus/README.md):
какой `.md` нужен для запуска, публикационного анализа, diversity-обоснования,
compiler-regression и triage.

## Что поддержано

- `AssertZero(Expression)`
- `RANGE` для witness-значений через bit decomposition
- `AND`/`XOR` для ширин меньше битности поля
- выходы `BrilligCall` как цели проверки

Если неподдержанный opcode может влиять на выбранную цель, она помечается как
`unsupported`. Opcode из другой компоненты witness-графа проверке не мешает.
