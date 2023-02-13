// Licensed under the Apache-2.0 license.
//
// generated by caliptra_registers_generator with rtl-caliptra repo at 0c9dc1a67e12e35892210271401299d44b9b37a9
//
#![allow(clippy::erasing_op)]
#![allow(clippy::identity_op)]
#[derive(Clone, Copy)]
pub struct RegisterBlock<TMmio: ureg::Mmio + core::borrow::Borrow<TMmio> = ureg::RealMmio> {
    ptr: *mut u32,
    mmio: TMmio,
}
impl RegisterBlock<ureg::RealMmio> {
    pub fn doe_reg() -> Self {
        unsafe { Self::new(0x10000000 as *mut u32) }
    }
}
impl<TMmio: ureg::Mmio + core::default::Default> RegisterBlock<TMmio> {
    pub unsafe fn new(ptr: *mut u32) -> Self {
        Self {
            ptr,
            mmio: core::default::Default::default(),
        }
    }
}
impl<TMmio: ureg::Mmio> RegisterBlock<TMmio> {
    /// # Safety
    ///
    /// The caller is responsible for ensuring that ptr is valid for
    /// volatile reads and writes at any of the offsets in this register
    /// block.
    pub unsafe fn new_with_mmio(ptr: *mut u32, mmio: TMmio) -> Self {
        Self { ptr, mmio }
    }
    /// 4 32-bit registers storing the 128-bit IV.
    ///
    /// Read value: [`u32`]; Write value: [`u32`]
    pub fn iv(&self) -> ureg::Array<4, ureg::RegRef<crate::doe::meta::Iv, &TMmio>> {
        unsafe {
            ureg::Array::new_with_mmio(
                self.ptr.wrapping_add(0 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
    /// Controls the de-obfuscation command to run
    ///
    /// Read value: [`doe::regs::CtrlReadVal`]; Write value: [`doe::regs::CtrlWriteVal`]
    pub fn ctrl(&self) -> ureg::RegRef<crate::doe::meta::Ctrl, &TMmio> {
        unsafe {
            ureg::RegRef::new_with_mmio(
                self.ptr.wrapping_add(0x10 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
    /// Provides status of the DOE block and the status of the flows it runs
    ///
    /// Read value: [`doe::regs::StatusReadVal`]; Write value: [`doe::regs::StatusWriteVal`]
    pub fn status(&self) -> ureg::RegRef<crate::doe::meta::Status, &TMmio> {
        unsafe {
            ureg::RegRef::new_with_mmio(
                self.ptr.wrapping_add(0x14 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
}
pub mod regs {
    //! Types that represent the values held by registers.
    #[derive(Clone, Copy)]
    pub struct CtrlReadVal(u32);
    impl CtrlReadVal {
        /// Indicates the command for DOE to run
        #[inline(always)]
        pub fn cmd(&self) -> super::enums::DoeCmdE {
            super::enums::DoeCmdE::try_from((self.0 >> 0) & 3).unwrap()
        }
        /// Key Vault entry to store the result.
        #[inline(always)]
        pub fn dest(&self) -> u32 {
            (self.0 >> 2) & 7
        }
        /// Construct a WriteVal that can be used to modify the contents of this register value.
        pub fn modify(self) -> CtrlWriteVal {
            CtrlWriteVal(self.0)
        }
    }
    impl From<u32> for CtrlReadVal {
        fn from(val: u32) -> Self {
            Self(val)
        }
    }
    impl From<CtrlReadVal> for u32 {
        fn from(val: CtrlReadVal) -> u32 {
            val.0
        }
    }
    #[derive(Clone, Copy)]
    pub struct CtrlWriteVal(u32);
    impl CtrlWriteVal {
        /// Indicates the command for DOE to run
        #[inline(always)]
        pub fn cmd(
            self,
            f: impl FnOnce(super::enums::selector::DoeCmdESelector) -> super::enums::DoeCmdE,
        ) -> Self {
            Self(
                (self.0 & !(3 << 0))
                    | (u32::from(f(super::enums::selector::DoeCmdESelector())) << 0),
            )
        }
        /// Key Vault entry to store the result.
        #[inline(always)]
        pub fn dest(self, val: u32) -> Self {
            Self((self.0 & !(7 << 2)) | ((val & 7) << 2))
        }
    }
    impl From<u32> for CtrlWriteVal {
        fn from(val: u32) -> Self {
            Self(val)
        }
    }
    impl From<CtrlWriteVal> for u32 {
        fn from(val: CtrlWriteVal) -> u32 {
            val.0
        }
    }
    #[derive(Clone, Copy)]
    pub struct StatusReadVal(u32);
    impl StatusReadVal {
        /// Status ready bit - Indicates if the core is ready to take a control command and process the block.
        #[inline(always)]
        pub fn ready(&self) -> bool {
            ((self.0 >> 0) & 1) != 0
        }
        /// Status valid bit - Indicates if the process is done and the results have been stored in the keyvault.
        #[inline(always)]
        pub fn valid(&self) -> bool {
            ((self.0 >> 1) & 1) != 0
        }
        /// UDS Flow Completed
        #[inline(always)]
        pub fn uds_flow_done(&self) -> bool {
            ((self.0 >> 2) & 1) != 0
        }
        /// FE flow completed
        #[inline(always)]
        pub fn fe_flow_done(&self) -> bool {
            ((self.0 >> 3) & 1) != 0
        }
        /// Clear Secrets flow completed
        #[inline(always)]
        pub fn deobf_secrets_cleared(&self) -> bool {
            ((self.0 >> 4) & 1) != 0
        }
    }
    impl From<u32> for StatusReadVal {
        fn from(val: u32) -> Self {
            Self(val)
        }
    }
    impl From<StatusReadVal> for u32 {
        fn from(val: StatusReadVal) -> u32 {
            val.0
        }
    }
}
pub mod enums {
    //! Enumerations used by some register fields.
    #[derive(Clone, Copy, Eq, PartialEq)]
    #[repr(u32)]
    pub enum DoeCmdE {
        DoeIdle = 0,
        DoeUds = 1,
        DoeFe = 2,
        DoeClearObfSecrets = 3,
    }
    impl DoeCmdE {
        #[inline(always)]
        pub fn doe_idle(&self) -> bool {
            *self == Self::DoeIdle
        }
        #[inline(always)]
        pub fn doe_uds(&self) -> bool {
            *self == Self::DoeUds
        }
        #[inline(always)]
        pub fn doe_fe(&self) -> bool {
            *self == Self::DoeFe
        }
        #[inline(always)]
        pub fn doe_clear_obf_secrets(&self) -> bool {
            *self == Self::DoeClearObfSecrets
        }
    }
    impl TryFrom<u32> for DoeCmdE {
        type Error = ();
        #[inline(always)]
        fn try_from(val: u32) -> Result<DoeCmdE, ()> {
            match val {
                0 => Ok(Self::DoeIdle),
                1 => Ok(Self::DoeUds),
                2 => Ok(Self::DoeFe),
                3 => Ok(Self::DoeClearObfSecrets),
                _ => Err(()),
            }
        }
    }
    impl From<DoeCmdE> for u32 {
        fn from(val: DoeCmdE) -> Self {
            val as u32
        }
    }
    pub mod selector {
        pub struct DoeCmdESelector();
        impl DoeCmdESelector {
            #[inline(always)]
            pub fn doe_idle(&self) -> super::DoeCmdE {
                super::DoeCmdE::DoeIdle
            }
            #[inline(always)]
            pub fn doe_uds(&self) -> super::DoeCmdE {
                super::DoeCmdE::DoeUds
            }
            #[inline(always)]
            pub fn doe_fe(&self) -> super::DoeCmdE {
                super::DoeCmdE::DoeFe
            }
            #[inline(always)]
            pub fn doe_clear_obf_secrets(&self) -> super::DoeCmdE {
                super::DoeCmdE::DoeClearObfSecrets
            }
        }
    }
}
pub mod meta {
    //! Additional metadata needed by ureg.
    pub type Iv = ureg::ReadWriteReg32<0, u32, u32>;
    pub type Ctrl =
        ureg::ReadWriteReg32<0, crate::doe::regs::CtrlReadVal, crate::doe::regs::CtrlWriteVal>;
    pub type Status = ureg::ReadOnlyReg32<crate::doe::regs::StatusReadVal>;
}
