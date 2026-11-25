//! Core worker scheduling controls. They do not change the run manifest or memo keys.

use std::num::NonZeroUsize;

pub(crate) const CORE_WORKERS: &str = "SP1_WORKER_NUM_CORE_WORKERS";
pub(crate) const CORE_QUEUE: &str = "SP1_WORKER_CORE_BUFFER_SIZE";

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct CorePool {
    workers: Option<NonZeroUsize>,
    queue: Option<NonZeroUsize>,
}

impl CorePool {
    pub(crate) fn parse(args: &[String]) -> Result<Self, String> {
        Ok(Self {
            workers: positive_option(args, "--core-workers")?,
            queue: positive_option(args, "--core-queue")?,
        })
    }

    pub(crate) fn overrides(&self) -> impl Iterator<Item = (&'static str, NonZeroUsize)> {
        [(CORE_WORKERS, self.workers), (CORE_QUEUE, self.queue)]
            .into_iter()
            .filter_map(|(name, value)| value.map(|value| (name, value)))
    }
}

fn positive_option(args: &[String], flag: &str) -> Result<Option<NonZeroUsize>, String> {
    let mut matches = args.iter().enumerate().filter(|(_, arg)| *arg == flag);
    let Some((index, _)) = matches.next() else {
        return Ok(None);
    };
    if matches.next().is_some() {
        return Err(format!("duplicate {flag}"));
    }
    args.get(index + 1)
        .and_then(|value| value.parse().ok())
        .map(Some)
        .ok_or_else(|| format!("{flag} requires a positive integer"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<CorePool, String> {
        CorePool::parse(&args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>())
    }

    #[test]
    fn keeps_defaults_and_allows_independent_overrides() {
        assert_eq!(parse(&["prove"]).unwrap().overrides().count(), 0);
        let pool = parse(&["prove", "--core-workers", "2", "--permits", "1"]).unwrap();
        assert_eq!(
            pool.overrides()
                .map(|(k, v)| (k, v.get()))
                .collect::<Vec<_>>(),
            [(CORE_WORKERS, 2)]
        );
        let pool = parse(&["prove", "--core-queue", "3", "--sp1-worker-defaults"]).unwrap();
        assert_eq!(
            pool.overrides()
                .map(|(k, v)| (k, v.get()))
                .collect::<Vec<_>>(),
            [(CORE_QUEUE, 3)]
        );
    }

    #[test]
    fn refuses_missing_zero_invalid_and_duplicate_values() {
        for args in [
            &["--core-workers"][..],
            &["--core-workers", "0"],
            &["--core-queue", "-1"],
            &["--core-queue", "--permits", "1"],
            &["--core-workers", "2", "--core-workers", "1"],
        ] {
            assert!(parse(args).is_err(), "accepted {args:?}");
        }
    }
}
