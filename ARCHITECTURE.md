# Архитектура

Проект не форкает Picus и не превращает ACIR в R1CS. Это адаптер между Noir
artifact JSON и Picus SMT.

```text
Noir artifact JSON
  -> acir::Program / acir::Circuit
  -> выбор fixed witnesses и целей проверки
  -> перевод поддержанных ACIR opcodes
  -> пропагация однозначности (леммы, без солвера)
  -> релаксированный UniquenessQuery   -- UNSAT здесь уже доказывает verified
  -> точный UniquenessQuery            -- только он даёт unsafe
  -> solver report
```

Три слоя намеренно упорядочены по цене. На реальном выводе компилятора основную
работу делает первый: хорошо скомпилированная схема определяет почти каждый
witness, и SMT-запрос стоит строить только для тех немногих, которые леммы не
закрыли.

## Проверка цели

Для каждого целевого witness строится self-composition query:

```text
exists W1, W2:
  SemACIR(W1)
  SemACIR(W2)
  fixed witnesses совпадают
  целевой witness отличается
```

Интерпретация результата:

- `SAT` на точном срезе: цель недоограничена;
- `UNSAT`: цель однозначно определяется поддержанной ACIR-семантикой;
- `UNKNOWN`: solver не смог доказать результат за отведенное время;
- `UNSUPPORTED`: на цель может влиять неподдержанный opcode.

## Перевод ACIR

- `AssertZero(Expression)` переводится в linear/nonlinear Picus constraints.
- `RANGE` переводится в boolean constraint для `num_bits = 1`, в `x = Σ 2^i b_i`
  с boolean bit-witnesses для меньших ширин поля, и в no-op для ширин не меньше
  битности поля.
- `AND`/`XOR` переводятся через bit decomposition входов и выхода для ширин меньше
  битности поля.
- `BrilligCall` считается недетерминированным источником; его выходы можно
  проверять как цели.
- Остальные blackbox calls, memory opcodes и ACIR calls пока не переводятся.

Неподдержанные opcodes не игнорируются молча. Сканер строит консервативный
witness-dependency graph и блокирует только цели из затронутой non-fixed
компоненты.
