# Примеры

В `examples/artifacts` лежат очищенные ACIR JSON: только `noir_version` и
`bytecode`, без debug symbols и локальных путей. Их можно запускать сразу после
клона репозитория.

```bash
cargo run -- scan examples/artifacts/unsafe_division_hint \
  --targets returns \
  --fixed all-params
```

Еще несколько запусков:

```bash
cargo run -- scan examples/artifacts/verified_division_hint \
  --targets returns \
  --fixed all-params

cargo run -- scan examples/artifacts/unsafe_auth_flag \
  --targets returns \
  --fixed all-params

cargo run -- scan examples/artifacts/unsafe_private_airdrop_nullifier \
  --targets returns \
  --fixed all-params

cargo run -- scan examples/artifacts/verified_private_airdrop_nullifier \
  --targets returns \
  --fixed all-params
```

## Ожидаемые результаты

| Пример | Результат |
| --- | --- |
| `unsafe_division_hint` | `unsafe` для возвращаемого quotient |
| `verified_division_hint` | `verified` для возвращаемого quotient |
| `unsafe_auth_flag` | `unsafe` для возвращаемого auth flag |
| `unsafe_private_airdrop_nullifier` | `unsafe` для возвращаемого nullifier |
| `verified_private_airdrop_nullifier` | `verified` для возвращаемого nullifier |

Если пересобираете артефакты сами, используйте тот же Noir revision, что и
`acir` dependency в `Cargo.toml`. ACIR serialization меняется между версиями.
