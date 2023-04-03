// Licensed under the Apache-2.0 license

// Based on device_lifecycle_e from RTL
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum DeviceLifecycle {
    #[default]
    Unprovisioned = 0b00,
    Manufacturing = 0b01,
    Reserved2 = 0b10,
    Production = 0b11,
}
impl TryFrom<u32> for DeviceLifecycle {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0b00 => Ok(Self::Unprovisioned),
            0b01 => Ok(Self::Manufacturing),
            0b10 => Ok(Self::Reserved2),
            0b11 => Ok(Self::Production),
            _ => Err(()),
        }
    }
}
impl From<DeviceLifecycle> for u32 {
    fn from(value: DeviceLifecycle) -> Self {
        value as u32
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SecurityState(u32);
impl From<u32> for SecurityState {
    fn from(value: u32) -> Self {
        Self(value)
    }
}
impl From<SecurityState> for u32 {
    fn from(value: SecurityState) -> Self {
        value.0
    }
}

impl SecurityState {
    pub fn debug_locked(self) -> bool {
        (self.0 & (1 << 2)) != 0
    }
    pub fn set_debug_locked(&mut self, val: bool) -> &mut Self {
        let mask = 1 << 2;
        if val {
            self.0 |= mask;
        } else {
            self.0 &= !mask
        };
        self
    }
    pub fn device_lifecycle(self) -> DeviceLifecycle {
        DeviceLifecycle::try_from(self.0 & 0x3).unwrap()
    }
    pub fn set_device_lifecycle(&mut self, val: DeviceLifecycle) -> &mut Self {
        self.0 |= (val as u32) & 0x3;
        self
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum U4 {
    #[default]
    X0 = 0x0,
    X1 = 0x1,
    X2 = 0x2,
    X3 = 0x3,
    X4 = 0x4,
    X5 = 0x5,
    X6 = 0x6,
    X7 = 0x7,
    X8 = 0x8,
    X9 = 0x9,
    Xa = 0xa,
    Xb = 0xb,
    Xc = 0xc,
    Xd = 0xd,
    Xe = 0xe,
    Xf = 0xf,
}
impl U4 {
    pub const B0000: Self = Self::X0;
    pub const B0001: Self = Self::X1;
    pub const B0010: Self = Self::X2;
    pub const B0011: Self = Self::X3;
    pub const B0100: Self = Self::X4;
    pub const B0101: Self = Self::X5;
    pub const B0110: Self = Self::X6;
    pub const B0111: Self = Self::X7;
    pub const B1000: Self = Self::X8;
    pub const B1001: Self = Self::X9;
    pub const B1010: Self = Self::Xa;
    pub const B1011: Self = Self::Xb;
    pub const B1100: Self = Self::Xc;
    pub const B1101: Self = Self::Xd;
    pub const B1110: Self = Self::Xe;
    pub const B1111: Self = Self::Xf;
}
impl From<U4> for u32 {
    fn from(value: U4) -> Self {
        value as u32
    }
}

#[derive(Default)]
pub struct Fuses {
    pub uds_seed: [u32; 12],
    pub field_entropy: [u32; 8],
    pub key_manifest_pk_hash: [u32; 12],
    pub key_manifest_pk_hash_mask: U4,
    pub owner_pk_hash: [u32; 12],
    pub fmc_key_manifest_svn: u32,
    pub runtime_svn: [u32; 4],
    pub anti_rollback_disable: bool,
    pub idevid_cert_attr: [u32; 24],
    pub idevid_manuf_hsm_id: [u32; 4],
    pub life_cycle: DeviceLifecycle,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test() {
        let mut ss = *SecurityState::default()
            .set_debug_locked(true)
            .set_device_lifecycle(DeviceLifecycle::Manufacturing);
        assert_eq!(0x5u32, ss.into());
        assert!(ss.debug_locked());
        assert_eq!(ss.device_lifecycle(), DeviceLifecycle::Manufacturing);
        ss.set_debug_locked(false);
        assert_eq!(0x1u32, ss.into());
    }
}