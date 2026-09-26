// УЯЗВИМАЯ схема. Доказательство «мой средний балл не ниже порога»
// без раскрытия самих оценок. Порог публичен, оценки и их число приватны.
unconstrained fn div_hint(total: u32, count: u32) -> u32 {
    if count == 0 { 0 } else { total / count }
}

fn main(scores: [u32; 8], count: u32, threshold: pub u32) -> pub u32 {
    assert(count <= 8);

    let mut total: u32 = 0;
    for i in 0..8 {
        if (i as u32) < count {
            total = total + scores[i];
        }
    }

    // Safety: частное проверяется ограничением ниже.
    let avg = unsafe { div_hint(total, count) };
    assert(avg * count == total);   // <-- при count = 0 выполняется для ЛЮБОГО avg

    assert(avg >= threshold);
    avg
}
