# Under-constrained public output via return_data bus (nightly-2026-08-11)


## Минимальное репро (1908 символов, 48 строк)

`main.nr` — сокращён с 5129 до 1908 (63%) через expression-level и line-based редьюсеры.

```noir
fn main(a: pub u128, mut b: i8) -> return_data i8 {
    let mut ctx_limit: u32 = 25_u32;
    b = {
        for idx_c in 64_i8 .. 71_i8 {
            b = {
                let d = b;
                match d {
                    73 => (((a as i64) >> (b as i64)) as i8),
                    _ => {
                        unsafe { func_1_proxy(..., b, ...) }
                    },
                }
            };
        };
        b
    };
    b
}
unconstrained fn func_1(...) -> i8 { { { { loop { ... } }; a.0.2 } } }
unconstrained fn func_1_proxy(...) -> i8 { func_1(a, b, c, (&mut ctx_limit)) }
```

## Входы

```
a = "11"   (public u128)
b = "8"    (private i8)
```

Честный выход: `0`. Подделанный выход: `1`.

## Корень

Класс `non-pinning-constraint` (раздел 3.2 отчёта). Механизм:

1. Компилятор генерирует `-> return_data i8`, выход идёт через `INIT RETURNDATA`, а не `return_values`
2. ACIR содержит `BrilligCall` с предикатом; хинт `w485` связан только `RANGE(8)` — проверкой разрядности, которая не фиксирует значение
3. Констрейнт `w485 = w2` (при `predicate=0`) — единственная связь возврата с хинтом
4. Чекер Noir принимает `RANGE(8)` за «ограничение, фиксирующее значение» (правило `is_against_const = constrained_values.len() == 1`)

**Важно:** это не задокументированный компромисс (ни `max-array-output-length`, ни `max-ancestor-distance` ни при чём — оба лимита подняты до 4096/500, чекер всё равно молчит).

## Проверка

```bash
nargo compile --force -Z enums --silence-warnings  # exit 0, 0 bug:
nargo execute --force -Z enums                     # output: 0
noir-picus-adapter mutate target/*.json --witness target/*.gz --attempts 4
# Результат: mutation search: 2073 attempt(s), 3 finding(s)
#   w2 0 -> 1 (265 witness(es) repaired)
```

## Статус

Готовая находка. Минимальное репро, корень изолирован, контроли пройдены, перепроверка `feasible --propagate-only` подтверждена. Можно публиковать.