# Two-Hint Cross-Constraint — новый класс недоограниченности

## Программа

```noir
unconstrained fn hint_a(x: Field) -> Field { x }
unconstrained fn hint_b(x: Field) -> Field { x }

fn main(a: Field) -> pub Field {
    let h1 = unsafe { hint_a(a) };
    let h2 = unsafe { hint_b(b) };
    assert(h1 * h2 == 0);  // две степени свободы!
    h1
}
```

Компилятор: **молчит** (exit 0, 0 `bug:`)
Адаптер: **4 находки** — w1 0→1, w2 0→1, w4 0→1, w1 0→1

## Чем отличается от non-pinning-constraint

| Характеристика | non-pinning (известный) | two-hint-cross (НОВЫЙ) |
|---|---|---|
| `constrained_values.len()` | 1 | ≥ 2 |
| Тип | `assert(h != 0)` | `assert(h1 + h2 == 0)`, `assert(h1 * h2 == 0)`, `(h1 & h2) == 0` |
| `is_against_const` | ✅ true (пропускает проверку) | ❌ false |
| `arguments_intersect` | не вызывается | ✅ **true** — ложно! |

## Корень

В `check_for_missing_brillig_constraints.rs`:

1. `constrained_values` содержит оба хинта (h1, h2)
2. `is_against_const = false` (len > 1) — **правильно**
3. `arguments_intersect` вызывается и возвращает `true`, потому что h2 = hint_b(b) и h1 = hint_a(a) имеют пересекающиеся входы... **но это не значит, что h1 определён!**

Уравнение `h1 + h2 == 0` имеет две степени свободы: для любого h1 можно подобрать h2 = -h1. Ни один из хинтов не зафиксирован, но чекер считает, что «достаточно ограничены».

## Покрытие

| Форма | Компилятор | Находка |
|---|---|---|
| `h1 * h2 == 0`, Field, один вход `a` | **молчит** | 3 |
| `h1 * h2 == 0`, Field, разные входы `a`, `b` | **молчит** | 4 |
| `h1 + h2 == 0`, Field | **молчит** | 4 |
| `(h1 & h2) == 0`, u8 | **молчит** | 4 |
| `h1 == h2`, Field | **bug:** ловит | — |

## Воспроизведение

```bash
nargo compile --force -Z enums
nargo execute --force -Z enums
noir-picus-adapter mutate target/*.json --witness target/*.gz --attempts 4
```