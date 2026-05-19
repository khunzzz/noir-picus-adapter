# Архитектура

Проект не форкает Picus и не превращает ACIR в R1CS. Это адаптер между Noir
artifact JSON и Picus SMT.

```text
Noir artifact JSON
  -> acir::Program / acir::Circuit
  -> выбор fixed witnesses и целей проверки
  -> перевод поддержанных ACIR opcodes
  -> picus_smt::query::UniquenessQuery
  -> solver report
```

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

- `SAT`: цель недоограничена;
- `UNSAT`: цель однозначно определяется поддержанной ACIR-семантикой;
- `UNKNOWN`: solver не смог доказать результат за отведенное время;
- `UNSUPPORTED`: на цель может влиять неподдержанный opcode.

## Перевод ACIR

- `AssertZero(Expression)` переводится в linear/nonlinear Picus constraints.
- `RANGE` с `num_bits = 1` переводится в boolean constraint.
- `BrilligCall` считается недетерминированным источником; его выходы можно
  проверять как цели.
- Остальные blackbox calls, memory opcodes и ACIR calls пока не переводятся.

Неподдержанные opcodes не игнорируются молча. Сканер строит консервативный
witness-dependency graph и блокирует только цели из затронутой non-fixed
компоненты.
