#[derive(Debug, Copy, Clone)]
pub enum IpFamily {
    V4,
    V6,
}

impl IpFamily {
    pub fn from_ipv4(ipv4: bool) -> IpFamily {
        if ipv4 {
            IpFamily::V4
        } else {
            IpFamily::V6
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ByIpFamily<T> {
    pub ipv4: T,
    pub ipv6: T,
}

impl<T> ByIpFamily<T> {
    pub fn try_new_with<F, E>(mut init: F) -> Result<ByIpFamily<T>, E>
    where
        F: FnMut(IpFamily) -> Result<T, E>,
    {
        Ok(ByIpFamily {
            ipv4: init(IpFamily::V4)?,
            ipv6: init(IpFamily::V6)?,
        })
    }

    pub fn by_family_mut(&mut self, family: IpFamily) -> &mut T {
        match family {
            IpFamily::V4 => &mut self.ipv4,
            IpFamily::V6 => &mut self.ipv6,
        }
    }
}
