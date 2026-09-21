use std::sync::Mutex;

/// Calculates Greatest Common Divisor
#[allow(clippy::many_single_char_names)]
pub const fn calc_gcd(mut x: isize, mut y: isize) -> isize {
    if x == 0 {
        return y;
    }

    if y == 0 {
        return x;
    }

    while y != 0 {
        let t = x % y;
        x = y;
        y = t;
    }

    x
}

#[derive(Debug)]
struct WrrCounters {
    i: isize,
    curr_weight: isize,
}

/// Implementation of Weighted Round Robin algorithm.
/// Based on http://kb.linuxvirtualserver.org/wiki/Weighted_Round-Robin_Scheduling
#[derive(Debug)]
pub struct Wrr<T> {
    items: Vec<(usize, T)>,
    n: isize,
    gcd: isize,
    max_weight: isize,
    counters: Mutex<WrrCounters>,
}

impl<T> Wrr<T> {
    pub fn new(items: Vec<(usize, T)>) -> Self {
        assert!(!items.is_empty(), "Wrr::new requires at least one item");

        let mut gcd = 0;
        let mut max_weight = 0;

        for v in &items {
            let w = v.0.cast_signed();
            gcd = calc_gcd(gcd, w);

            if w > max_weight {
                max_weight = w;
            }
        }

        Self {
            n: items.len().cast_signed(),
            items,
            gcd,
            max_weight,
            counters: Mutex::new(WrrCounters {
                i: -1,
                curr_weight: 0,
            }),
        }
    }

    /// Returns a reference to the next item according to weights
    pub fn next(&self) -> &T {
        let mut c = self.counters.lock().unwrap();

        loop {
            c.i = (c.i + 1) % self.n;
            if c.i == 0 {
                c.curr_weight -= self.gcd;
                if c.curr_weight <= 0 {
                    c.curr_weight = self.max_weight;
                }
            }

            if (self.items[c.i.cast_unsigned()].0.cast_signed()) >= c.curr_weight {
                return &self.items[c.i.cast_unsigned()].1;
            }
        }
    }
}

#[cfg(test)]
mod test {
    use ahash::AHashMap;

    use super::*;

    #[test]
    fn test_wrr() {
        let items = vec![
            (2, "foo".to_string()),
            (3, "bar".to_string()),
            (5, "baz".to_string()),
        ];

        let wrr = Wrr::new(items);
        let mut hits = AHashMap::new();

        // Do 1k selections
        for _ in 0..1000 {
            let item = wrr.next();
            hits.entry(item.clone())
                .and_modify(|x| *x += 1)
                .or_insert(1);
        }

        // Make sure that we get the distribution according to the weights
        assert_eq!(hits["foo"], 200);
        assert_eq!(hits["bar"], 300);
        assert_eq!(hits["baz"], 500);
    }

    /// Collects `n` consecutive picks
    fn picks(wrr: &Wrr<&'static str>, n: usize) -> Vec<&'static str> {
        (0..n).map(|_| *wrr.next()).collect()
    }

    /// Counts the occurrences of each item in the sequence
    fn tally(seq: &[&'static str]) -> AHashMap<&'static str, usize> {
        let mut h = AHashMap::new();
        for v in seq {
            *h.entry(*v).or_insert(0usize) += 1;
        }
        h
    }

    #[test]
    fn test_calc_gcd() {
        // Zero is the identity element
        assert_eq!(calc_gcd(0, 0), 0);
        assert_eq!(calc_gcd(0, 7), 7);
        assert_eq!(calc_gcd(7, 0), 7);

        // Commutative
        assert_eq!(calc_gcd(12, 18), 6);
        assert_eq!(calc_gcd(18, 12), 6);

        // Coprime
        assert_eq!(calc_gcd(13, 7), 1);
        assert_eq!(calc_gcd(1, 1000), 1);

        // Equal & multiples
        assert_eq!(calc_gcd(9, 9), 9);
        assert_eq!(calc_gcd(1024, 64), 64);
        assert_eq!(calc_gcd(isize::MAX, isize::MAX), isize::MAX);

        // Magnitude is correct for negative inputs, the sign follows Rust's
        // remainder semantics (it takes the sign of the dividend)
        assert_eq!(calc_gcd(-4, 6), 2);
        assert_eq!(calc_gcd(6, -4), 2);
        assert_eq!(calc_gcd(-4, -6), -2);

        // It's a `const fn`
        const G: isize = calc_gcd(48, 180);
        assert_eq!(G, 12);
    }

    #[test]
    #[should_panic(expected = "Wrr::new requires at least one item")]
    fn test_wrr_empty_panics() {
        let _ = Wrr::<u8>::new(vec![]);
    }

    #[test]
    fn test_wrr_single_item() {
        // Any weight, including zero, must always yield the only item and never spin forever
        for w in [0, 1, 7] {
            let wrr = Wrr::new(vec![(w, "only")]);
            assert_eq!(picks(&wrr, 10), vec!["only"; 10]);
        }
    }

    #[test]
    fn test_wrr_equal_weights_is_plain_round_robin() {
        let wrr = Wrr::new(vec![(3, "a"), (3, "b"), (3, "c")]);
        // With equal weights the GCD equals the weight, so every item is
        // eligible on every round -> strict round-robin in insertion order.
        assert_eq!(
            picks(&wrr, 9),
            vec!["a", "b", "c", "a", "b", "c", "a", "b", "c"]
        );
    }

    #[test]
    fn test_wrr_all_zero_weights_degrades_to_round_robin() {
        // All-zero weights give gcd == 0 and max_weight == 0, so the eligibility
        // check `0 >= 0` always passes: plain round-robin, no infinite loop.
        let wrr = Wrr::new(vec![(0, "a"), (0, "b"), (0, "c")]);
        assert_eq!(picks(&wrr, 6), vec!["a", "b", "c", "a", "b", "c"]);
    }

    #[test]
    fn test_wrr_zero_weight_is_starved() {
        // A zero-weighted item never gets picked while a positive-weighted one exists
        let wrr = Wrr::new(vec![(0, "off"), (2, "on")]);
        assert_eq!(tally(&picks(&wrr, 100)), {
            let mut h = AHashMap::new();
            h.insert("on", 100);
            h
        });

        let wrr = Wrr::new(vec![(0, "off1"), (0, "off2"), (3, "on")]);
        let hits = tally(&picks(&wrr, 50));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits["on"], 50);
    }

    #[test]
    fn test_wrr_exact_sequence_and_period() {
        let wrr = Wrr::new(vec![(2, "a"), (3, "b"), (5, "c")]);

        // The schedule is fully deterministic: one full cycle is
        // sum(weights) / gcd == 10 picks long.
        let cycle = vec!["c", "c", "b", "c", "a", "b", "c", "a", "b", "c"];
        assert_eq!(picks(&wrr, 10), cycle);

        // ...and it repeats verbatim, with the per-cycle hits exactly matching the weights
        for _ in 0..3 {
            let next = picks(&wrr, 10);
            assert_eq!(next, cycle);
            let hits = tally(&next);
            assert_eq!(hits["a"], 2);
            assert_eq!(hits["b"], 3);
            assert_eq!(hits["c"], 5);
        }
    }

    #[test]
    fn test_wrr_weights_are_reduced_by_gcd() {
        // 4:6 reduces to 2:3, so a cycle is 10/2 == 5 picks and not 10
        let wrr = Wrr::new(vec![(4, "a"), (6, "b")]);
        assert_eq!(picks(&wrr, 5), vec!["b", "a", "b", "a", "b"]);

        let hits = tally(&picks(&wrr, 100));
        assert_eq!(hits["a"], 40);
        assert_eq!(hits["b"], 60);
    }

    #[test]
    fn test_wrr_lopsided_weights() {
        // A very large weight next to a tiny one still yields the exact ratio
        let wrr = Wrr::new(vec![(1, "small"), (1000, "big")]);
        let hits = tally(&picks(&wrr, 2002));
        assert_eq!(hits["small"], 2);
        assert_eq!(hits["big"], 2000);
    }

    #[test]
    fn test_wrr_deterministic_across_instances() {
        let items = || vec![(1, "a"), (4, "b"), (6, "c"), (9, "d")];
        let a = Wrr::new(items());
        let b = Wrr::new(items());
        assert_eq!(picks(&a, 50), picks(&b, 50));

        // Reordering the items changes the schedule but not the distribution
        let c = Wrr::new(vec![(9, "d"), (6, "c"), (4, "b"), (1, "a")]);
        let seq_a = picks(&a, 20);
        let seq_c = picks(&c, 20);
        assert_ne!(seq_a, seq_c);
        assert_eq!(tally(&picks(&a, 400)), tally(&picks(&c, 400)));
    }

    #[test]
    fn test_wrr_concurrent_selection_keeps_distribution() {
        let wrr = Wrr::new(vec![(2, "a"), (3, "b"), (5, "c")]);
        const THREADS: usize = 8;
        const PER_THREAD: usize = 1250;

        let results = std::thread::scope(|s| {
            let handles = (0..THREADS)
                .map(|_| s.spawn(|| picks(&wrr, PER_THREAD)))
                .collect::<Vec<_>>();

            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect::<Vec<_>>()
        });

        // The mutex serializes the pickers, so the union of all picks is still
        // a valid WRR schedule and the global distribution is exact.
        let all = results.into_iter().flatten().collect::<Vec<_>>();
        assert_eq!(all.len(), THREADS * PER_THREAD);
        let hits = tally(&all);
        assert_eq!(hits["a"], 2000);
        assert_eq!(hits["b"], 3000);
        assert_eq!(hits["c"], 5000);
    }

    #[test]
    fn test_wrr_period_and_share_invariants() {
        // For any weight set with a non-zero GCD the schedule is periodic with a
        // period of sum(weights)/gcd picks, and within one period every item is
        // picked exactly weight/gcd times.
        for weights in [
            vec![1usize, 1],
            vec![1, 2, 3],
            vec![5, 5, 5, 5],
            vec![7, 1],
            vec![6, 10, 15],
            vec![2, 4, 8, 16],
            vec![1, 1, 1, 1, 1, 1, 1],
            // Zero-weighted items simply never get scheduled
            vec![0, 3],
            vec![0, 2, 4],
        ] {
            let gcd = weights
                .iter()
                .fold(0isize, |a, w| calc_gcd(a, (*w).cast_signed()))
                .unsigned_abs();
            let period = weights.iter().sum::<usize>() / gcd;

            let wrr = Wrr::new(weights.iter().copied().zip(0usize..).collect::<Vec<_>>());
            let pick = |n: usize| (0..n).map(|_| *wrr.next()).collect::<Vec<_>>();

            // Two consecutive periods are identical, i.e. the state really does
            // return to the top of the schedule after `period` picks
            let first = pick(period);
            assert_eq!(first, pick(period), "weights {weights:?}: not periodic");

            for (i, w) in weights.iter().enumerate() {
                assert_eq!(
                    first.iter().filter(|x| **x == i).count(),
                    *w / gcd,
                    "weights {weights:?}: item {i} got the wrong share of {first:?}"
                );
            }
        }
    }

    #[test]
    fn test_wrr_schedule_depends_on_item_order() {
        // Weights are fixed at construction time - there is no runtime update
        // API, so a new weight set means a new `Wrr` starting from the top.
        // The same 3:1 ratio yields a different schedule depending on which
        // side the heavy item sits on.
        let a = Wrr::new(vec![(1, "x"), (3, "y")]);
        assert_eq!(picks(&a, 4), vec!["y", "y", "x", "y"]);

        let b = Wrr::new(vec![(3, "x"), (1, "y")]);
        assert_eq!(picks(&b, 4), vec!["x", "x", "x", "y"]);

        // ...but the shares are identical
        assert_eq!(tally(&picks(&a, 400))["x"], 100);
        assert_eq!(tally(&picks(&b, 400))["x"], 300);
    }
}
