#![feature(addr_parse_ascii)]

mod ip_family;
mod keyed_limiter;
mod masked_ip;

use std::{
    error::Error,
    hash::BuildHasherDefault,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroU32,
    time::{Duration, Instant},
};

use clap::Parser;
use governor::Quota;
use ipset::{
    types::{AddOption, HashNet, NetDataType},
    Session,
};
use log::{debug, error, info};
use mini_moka::unsync::Cache;
use rustc_hash::FxHasher;

use crate::{
    ip_family::{ByIpFamily, IpFamily},
    keyed_limiter::KeyedLimiter,
    masked_ip::{Mask, MaskedIpAddr},
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// The number of events that has to be exceeded before a ban decision.
    /// Combines with `bl_period` to determine the exact rate limit.
    /// see: https://github.com/antifuchs/governor/blob/master/governor/src/quota.rs#L9
    #[arg(long)]
    pub bl_threshold: u32,

    /// The amount of time before the rate limiter is fully replenished.
    /// Uses humantime to parse the duration.
    /// See: https://docs.rs/humantime/latest/humantime/ for details
    ///
    /// Combines with `bl_threshold` to determine the exact rate limit
    /// see: https://github.com/antifuchs/governor/blob/master/governor/src/quota.rs#L9
    #[arg(long, default_value = "0s", value_parser = parse_duration)]
    pub bl_period: Duration,

    /// Recidivists get banned longer for their subsequent bans.
    /// This reperesents the amount of time we'll keep the history around.
    /// Everytime we :hammer-time: them, it will reset this countdown.
    /// The user must avoid an ipset ban for this long before their
    /// previous ipset bans are forgotten.
    ///
    /// Uses humantime to parse the duration.
    /// See: https://docs.rs/humantime/latest/humantime/ for details
    #[arg(long, value_parser = parse_duration)]
    pub ipset_ban_ttl: Duration,

    /// The time of the first ban. Each subsequent ban will be increased
    /// linearly by this amount (resulting in --ipset-base-time * ban count).
    ///
    /// Uses humantime to parse the duration.
    /// See: https://docs.rs/humantime/latest/humantime/ for details
    #[arg(long, value_parser = parse_duration)]
    pub ipset_base_time: Duration,

    /// The name of the ipset for IPv4.
    #[arg(long)]
    pub ipset_ipv4_name: String,

    /// The name of the ipset for IPv6.
    #[arg(long)]
    pub ipset_ipv6_name: String,

    /// Number of IPv4 prefix bits. 32 to ban individual IPs.
    #[arg(long, default_value = "32")]
    ipv4_prefix: u8,

    /// Number of IPv6 prefix bits. 128 to ban individual IPs. 64 to ban subnets
    /// typically assigned by ISPs.
    #[arg(long, default_value = "64")]
    ipv6_prefix: u8,

    /// The number of seconds to accumulate ban counts before reporting and
    /// resetting.
    ///
    /// Uses humantime to parse the duration.
    /// See: https://docs.rs/humantime/latest/humantime/ for details
    #[arg(long, default_value = "10s", value_parser = parse_duration)]
    pub reporting_ban_time_period: Duration,

    /// The number of seconds to accumulate ip counts before reporting and
    /// resetting.
    ///
    /// Uses humantime to parse the duration.
    /// See: https://docs.rs/humantime/latest/humantime/ for details
    #[arg(long, default_value = "10s", value_parser = parse_duration)]
    pub reporting_ip_time_period: Duration,

    /// Initial capacity of the rate limiter table and recidivism cache.
    /// Choose a value large enough for a typical DDOS, to avoid gc and memory
    /// allocation when under attack.
    #[arg(long, default_value = "100000")]
    pub cache_initial_capacity: usize,

    /// The maximum number of entries to keep in the recidivism cache.
    #[arg(long, default_value = "500000")]
    pub cache_max_size: u64,

    /// Do not actually actually test or manage ipsets. Useful for test runs
    /// without privileges.
    #[arg(long)]
    pub dry_run: bool,
}

impl Args {
    fn seconds_to_ban(&self, ban_count: u32) -> u32 {
        self.ipset_base_time
            .checked_mul(ban_count)
            .and_then(|time| u32::try_from(time.as_secs()).ok())
            .unwrap_or(u32::MAX)
    }
}

fn parse_duration(s: &str) -> Result<Duration, humantime::DurationError> {
    s.parse::<humantime::Duration>().map(Into::into)
}

pub struct Leroy {
    mask: Mask,

    sessions: ByIpFamily<Session<HashNet>>,

    ip_rate_limiters: Option<KeyedLimiter<MaskedIpAddr, BuildHasherDefault<FxHasher>>>,
    ipset_cache: Cache<MaskedIpAddr, (), BuildHasherDefault<FxHasher>>,
    recidivism_counts: Cache<MaskedIpAddr, u32, BuildHasherDefault<FxHasher>>,

    line_count: u64,
    line_count_start: Instant,

    ban_count: u64,
    ban_count_start: Instant,

    args: Args,
}

impl Leroy {
    pub fn new(args: Args) -> Result<Leroy, Box<dyn Error>> {
        let mask = Mask::new(ByIpFamily {
            ipv4: args.ipv4_prefix,
            ipv6: args.ipv6_prefix,
        });
        Ok(Leroy {
            mask: mask.clone(),
            sessions: ByIpFamily::try_new_with::<_, Box<dyn Error>>(|family| {
                let (name, localhost) = match family {
                    IpFamily::V4 => (&args.ipset_ipv4_name, IpAddr::V4(Ipv4Addr::LOCALHOST)),
                    IpFamily::V6 => (&args.ipset_ipv6_name, IpAddr::V6(Ipv6Addr::LOCALHOST)),
                };
                let mut session = Session::<HashNet>::new(name.clone());
                let localhost = mask.apply(&localhost);
                if !args.dry_run {
                    session.test(NetDataType::from(localhost)).map_err(|err| {
                        format!("Failed to test set {name:?}: {err}. Please create before running.")
                    })?;
                }
                Ok(session)
            })?,
            ip_rate_limiters: match NonZeroU32::new(args.bl_threshold) {
                Some(bl_threshold) => Some(KeyedLimiter::new(
                    Quota::with_period(args.bl_period)
                        .ok_or_else(|| format!("--bl-period must be non-zero"))?
                        .allow_burst(bl_threshold),
                    args.cache_initial_capacity,
                    BuildHasherDefault::default(),
                )),
                None => None, // ban on sight
            },
            ipset_cache: Cache::builder()
                .initial_capacity(args.cache_initial_capacity)
                .max_capacity(args.cache_max_size)
                .time_to_live(args.ipset_base_time.saturating_sub(Duration::from_secs(1)))
                .build_with_hasher(Default::default()),
            recidivism_counts: Cache::builder()
                .initial_capacity(args.cache_initial_capacity)
                .max_capacity(args.cache_max_size)
                .time_to_live(args.ipset_ban_ttl)
                .build_with_hasher(Default::default()),
            line_count: 0,
            ban_count: 0,
            line_count_start: Instant::now(),
            ban_count_start: Instant::now(),
            args,
        })
    }

    pub fn handle_line(&mut self, line: &Vec<u8>) {
        self.line_count += 1;

        match IpAddr::parse_ascii(line) {
            Ok(ip) => {
                let ip = self.mask.apply(&ip);
                if self
                    .ip_rate_limiters
                    .as_mut()
                    .map_or(true, |l| l.check_key(&ip).is_err())
                {
                    self.ban(ip);
                }
            }
            Err(err) => error!(
                "Error parsing IP from {:?}: {}",
                String::from_utf8_lossy(line),
                err
            ),
        };

        if self.line_count % 10 == 0
            && self.line_count_start.elapsed() > self.args.reporting_ip_time_period
        {
            info!(
                "Seen {} lines since {:?}",
                self.line_count,
                self.line_count_start.elapsed()
            );
            self.line_count = 0;
            self.line_count_start = Instant::now();
        }
    }

    fn ban(&mut self, ip: MaskedIpAddr) {
        if self.ipset_cache.contains_key(&ip) {
            debug!("{ip} already banned");
            return;
        }

        let recidivism: u32 = *self.recidivism_counts.get(&ip).unwrap_or(&0) + 1;
        let timeout = self.args.seconds_to_ban(recidivism);

        let ban_result = if self.args.dry_run {
            Ok(true)
        } else {
            self.sessions
                .by_family_mut(ip.family())
                .add(NetDataType::from(ip), vec![AddOption::Timeout(timeout)])
        };

        match ban_result {
            Ok(false) => debug!("{ip} already banned, but was no longer cached"),
            Ok(true) => {
                info!("Banned {ip} for {timeout}s (recidivism: {recidivism})");
                self.ban_count += 1;
                self.ipset_cache.insert(ip, ());
                self.recidivism_counts.insert(ip, recidivism);
            }
            Err(err) => error!("Unable to add {ip} to set: {err}"),
        }

        if self.ban_count_start.elapsed() > self.args.reporting_ban_time_period {
            info!(
                "Banned {} ips in the past {:?}",
                self.ban_count,
                self.ban_count_start.elapsed()
            );
            self.ban_count = 0;
            self.ban_count_start = Instant::now();
        }
    }
}
