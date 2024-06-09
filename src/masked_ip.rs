use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use ipset::types::NetDataType;

use crate::{ByIpFamily, IpFamily};

#[derive(Debug, Clone)]
pub struct Mask {
    prefix_bits: ByIpFamily<u8>,
    ipv4_mask: Ipv4Addr,
    ipv6_mask: Ipv6Addr,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct MaskedIpAddr {
    ip: IpAddr,
    prefix_bits: u8,
}

impl MaskedIpAddr {
    pub fn family(&self) -> IpFamily {
        IpFamily::from_ipv4(self.ip.is_ipv4())
    }
}

impl From<MaskedIpAddr> for NetDataType {
    fn from(masked_ip: MaskedIpAddr) -> NetDataType {
        NetDataType::new(masked_ip.ip, masked_ip.prefix_bits)
    }
}

impl fmt::Display for MaskedIpAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.ip, self.prefix_bits)
    }
}

impl Mask {
    pub fn new(prefix_bits: ByIpFamily<u8>) -> Mask {
        Mask {
            prefix_bits,
            ipv4_mask: Ipv4Addr::from_bits((0xFFFF_FFFF) << (32 - prefix_bits.ipv4)),
            ipv6_mask: Ipv6Addr::from_bits(
                (0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF) << (128 - prefix_bits.ipv6),
            ),
        }
    }

    pub fn apply(&self, ip: &IpAddr) -> MaskedIpAddr {
        match ip {
            IpAddr::V4(ip) => MaskedIpAddr {
                ip: IpAddr::V4(ip & self.ipv4_mask),
                prefix_bits: self.prefix_bits.ipv4,
            },
            IpAddr::V6(ip) => MaskedIpAddr {
                ip: IpAddr::V6(ip & self.ipv6_mask),
                prefix_bits: self.prefix_bits.ipv6,
            },
        }
    }
}
