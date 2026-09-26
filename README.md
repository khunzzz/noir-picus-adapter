# noir-picus-adapter

Проверка Noir ACIR-артефактов на недоограниченные значения.

Инструмент берет JSON, который выдает `nargo compile`, выбирает возвращаемые
значения и выходы `BrilligCall`, переводит поддержанные ограничения ACIR в Picus
SMT и проверяет, может ли один и тот же набор входов дать разные значения
целевого witness.

## Требования

- Rust 1.89+
- `git`, `bash`, `make`, `cmake`
- C/C++ toolchain
- `libclang` для `bindgen`

Зависимости на Noir и Picus закреплены в `Cargo.toml` по git revision. Локально
клонировать Noir или Picus не нужно.

### Сборка без пересборки cvc5

По умолчанию `cvc5-ff-sys` собирает cvc5 из исходников: десятки минут и
несколько гигабайт на каждой машине. Этого можно не делать — официальные
статические релизы cvc5 содержат всё нужное, включая CoCoA для конечных полей:

```bash
curl -sSL -o cvc5.zip \
  https://github.com/cvc5/cvc5/releases/download/cvc5-1.3.1/cvc5-Linux-x86_64-static-gpl.zip
unzip -q cvc5.zip
export CVC5_LIB_DIR="$PWD/cvc5-Linux-x86_64-static-gpl/lib"
export CVC5_INCLUDE_DIR="$PWD/cvc5-Linux-x86_64-static-gpl/include"
cargo build --release
```

Версия должна совпадать с `[package.metadata.cvc5]` в `cvc5-ff-sys`
(сейчас 1.3.1). `build.rs` этого проекта дольнковывает CLN и GLPK, которые
релизный архив кладёт отдельно, а список библиотек в `cvc5-ff-sys` не
упоминает.

Если `bindgen` не находит `stddef.h` (libclang без своих заголовков):

```bash
export BINDGEN_EXTRA_CLANG_ARGS="-I/usr/lib/gcc/x86_64-linux-gnu/13/include"
```

Сборка `z3` через cmake по умолчанию однопоточная; `CMAKE_BUILD_PARALLEL_LEVEL`
её распараллеливает.

### Если сборка из исходников всё же нужна, а прав администратора нет

Способ выше (готовый релиз cvc5) предпочтителен и почти всегда достаточен.
Но если cvc5 приходится собирать, ему нужны три вещи, которых на голой машине
обычно нет, и все три ставятся в домашний каталог:

```bash
uv tool install cmake                      # cmake
uv venv --seed ~/.cvc5venv                 # pip: cvc5 ищет его через FindPip.cmake
export PATH="$HOME/.cvc5venv/bin:$HOME/.local/bin:$PATH"
export VIRTUAL_ENV="$HOME/.cvc5venv"

# m4: нужен GMP, который cvc5 собирает из исходников
curl -sL https://ftp.gnu.org/gnu/m4/m4-1.4.19.tar.gz | tar xz
cd m4-1.4.19 && ./configure --prefix="$HOME/.local" && make -j2 && make install
```

Порядок отказов именно такой: сначала не найдётся `cmake`, затем `pip`, затем
`m4` (внутри configure GMP), и только потом `stddef.h` для `bindgen`. Каждый
следующий виден лишь после того, как устранён предыдущий.

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
cargo run -- scan <artifact> --no-solve            # только пропагация, без SMT
cargo run -- scan <artifact> --max-range-bits 32   # бюджет битовой декомпозиции
cargo run -- scan <artifact> --exit-code-on-finding
```

`--no-solve` переводит все нерешённые пропагацией цели в `unknown` и не зовёт
солвер. Это быстрый способ измерить, сколько работы снимает слой лемм, и
разобраться со схемой, на которой солвер уходит в разнос.

`--exit-code-on-finding` даёт код возврата 1 при `unsafe` и 2 при ошибке, чтобы
CI и фаззинг-обвязка не разбирали JSON.

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
- `RANGE` для witness-значений через bit decomposition (до `--max-range-bits`)
- `AND`/`XOR` для ширин меньше битности поля
- `MemoryInit`/`MemoryOp` через one-hot селекторы
- детерминированные blackbox через абстракцию детерминизма
- выходы `BrilligCall` как цели проверки

Если неподдержанный opcode может влиять на выбранную цель, она помечается как
`unsupported`. Opcode из другой компоненты witness-графа проверке не мешает.

## Как устроена проверка

Три слоя, от дешёвого к дорогому:

1. **Пропагация однозначности** (`src/translate/uniqueness.rs`) — леммы,
   доказывающие, что wire определён однозначно, без солвера. Покрывает идиомы,
   которые компилятор Noir вставляет сам: евклидово деление, обратный элемент,
   гаджет IsZero, чистые blackbox.
2. **Релаксированный SMT-запрос** — конус, срезанный по определённым wire. Это
   надмножество решений, поэтому `UNSAT` здесь уже доказывает однозначность.
3. **Точный SMT-запрос** — только для целей, где релаксированный запрос нашёл
   расхождение. Только его вердикт становится `unsafe`.
4. **Сертификат** — обе найденные раскладки witness перепроверяются напрямую по
   опкодам ACIR, минуя перевод. Сертифицированная находка не может быть
   артефактом ошибки перевода; `refuted` означает баг в самом инструменте.

Обоснование корректности каждого слоя — в [SOUNDNESS.md](SOUNDNESS.md).

## Поиск багов компилятора

`tools/noir_gen.py` генерирует случайные программы на Noir, `tools/fuzz_campaign.py`
прогоняет их через `nargo compile` и скан. Сгенерированная программа —
детерминированная функция своих аргументов, поэтому при `--fixed all-params`
любой witness с двумя возможными значениями означает, что недоограниченную
схему выпустил **компилятор**:

```bash
python3 tools/fuzz_campaign.py \
  --adapter ./target/release/noir-picus-adapter \
  --nargo "$(which nargo)" \
  --out findings --mode pure --count 200
```
