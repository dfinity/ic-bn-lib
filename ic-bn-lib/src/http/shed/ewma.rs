/// Implementation of Exponential Weighted Moving Average.
/// https://en.wikipedia.org/wiki/Exponential_smoothing#Basic_(simple)_exponential_smoothing
#[derive(Debug)]
pub struct EWMA {
    alpha: f64,
    new: bool,
    value: f64,
}

impl EWMA {
    /// Create new `EWMA`
    pub fn new(alpha: f64) -> Self {
        assert!((0.0..=1.0).contains(&alpha));

        Self {
            new: true,
            value: 0.0,
            alpha,
        }
    }

    /// Record new measurement
    pub fn add(&mut self, v: f64) {
        if self.new {
            self.new = false;
            self.value = v;
            return;
        }

        // Use FMA instruction for faster and more precise calculation of a*b + c
        self.value = self.alpha.mul_add(v - self.value, self.value)
    }

    /// Get the average
    pub const fn get(&self) -> Option<f64> {
        if self.new {
            return None;
        }

        Some(self.value)
    }
}

/// Implementation of Double Exponential Weighted Moving Average.
/// https://en.wikipedia.org/wiki/Exponential_smoothing#Double_exponential_smoothing_(Holt_linear)
#[derive(Debug)]
pub struct DEWMA {
    alpha: f64,
    beta: f64,

    iter: u8,
    value: f64,
    trend: f64,
}

impl DEWMA {
    /// Create new `DEWMA`
    pub fn new(alpha: f64, beta: f64) -> Self {
        assert!((0.0..=1.0).contains(&alpha));
        assert!((0.0..=1.0).contains(&beta));

        Self {
            iter: 0,
            value: 0.0,
            trend: 0.0,
            alpha,
            beta,
        }
    }

    /// Add a measurement
    pub fn add(&mut self, v: f64) {
        if self.iter == 0 {
            self.iter += 1;
            self.value = v;
            return;
        } else if self.iter == 1 {
            // Initialize the trend on 2nd measurement
            self.iter += 1;
            self.trend = v - self.value;
        }

        let value_old = self.value;

        // Use FMA instruction for faster and more precise calculation of a*b + c
        self.value = self
            .alpha
            .mul_add(v, (1.0 - self.alpha) * (self.value + self.trend));
        self.trend = self
            .beta
            .mul_add(self.value - value_old, (1.0 - self.beta) * self.trend);
    }

    /// Get the average
    pub fn get(&self, m: f64) -> Option<f64> {
        // The function is undefined for the 1st measurement
        if self.iter < 2 {
            return None;
        }

        Some(m.mul_add(self.trend, self.value))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_ewma() {
        let mut e = EWMA::new(0.7);

        assert!(e.get().is_none());
        e.add(100.0);
        assert_eq!(e.get().unwrap(), 100.0);
        e.add(150.0);
        assert_eq!(e.get().unwrap(), 135.0);
        e.add(150.0);
        assert_eq!(e.get().unwrap(), 145.5);
        e.add(150.0);
        assert_eq!(e.get().unwrap(), 148.65);
    }

    #[test]
    fn test_dewma() {
        let mut e = DEWMA::new(0.7, 0.6);

        e.add(100.0);
        assert!(e.get(0.0).is_none());
        e.add(150.0);
        assert_eq!(e.get(0.0).unwrap(), 150.0);
        e.add(200.0);
        assert_eq!(e.get(0.0).unwrap(), 200.0);
        e.add(300.0);
        assert_eq!(e.get(0.0).unwrap(), 285.0);
        assert_eq!(e.get(1.0).unwrap(), 356.0);
        e.add(300.0);
        assert_eq!(e.get(0.0).unwrap(), 316.8);
    }
}
