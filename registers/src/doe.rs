// Licensed under the Apache-2.0 license.
//
// generated by caliptra_registers_generator with rtl-caliptra repo at f1feedff601b55715ccaed60ebfcd83543617752
//
#![allow(clippy::erasing_op)]
#![allow(clippy::identity_op)]
#[derive(Clone, Copy)]
pub struct RegisterBlock(*mut u32);
impl RegisterBlock {
    /// # Safety
    ///
    /// The caller is responsible for ensuring that ptr is valid for
    /// volatile reads and writes at any of the offsets in this register
    /// block.
    pub unsafe fn new(ptr: *mut u32) -> Self {
        Self(ptr)
    }
    pub fn doe_reg() -> Self {
        unsafe { Self::new(0x10000000 as *mut u32) }
    }
    /// 4 32-bit registers storing the 128-bit IV.
    ///
    /// Read value: [`u32`]; Write value: [`u32`]
    pub fn iv(&self) -> ureg::Array<4, ureg::RegRef<crate::doe::meta::Iv>> {
        unsafe { ureg::Array::new(self.0.wrapping_add(0 / core::mem::size_of::<u32>())) }
    }
    /// Controls the de-obfuscation command to run
    ///
    /// Read value: [`doe::regs::CtrlReadVal`]; Write value: [`doe::regs::CtrlWriteVal`]
    pub fn ctrl(&self) -> ureg::RegRef<crate::doe::meta::Ctrl> {
        unsafe { ureg::RegRef::new(self.0.wrapping_add(0x10 / core::mem::size_of::<u32>())) }
    }
    /// One 2-bit register including the following flags:
    /// bit #0: READY : ​Indicates if the core is ready to take
    ///                a control command and process the block.  
    /// bit #1: Valid: ​Indicates if the process is done and the
    ///                results have been stored in the keyvault.
    ///
    /// Read value: [`doe::regs::StatusReadVal`]; Write value: [`doe::regs::StatusWriteVal`]
    pub fn status(&self) -> ureg::RegRef<crate::doe::meta::Status> {
        unsafe { ureg::RegRef::new(self.0.wrapping_add(0x14 / core::mem::size_of::<u32>())) }
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
        /// Status ready bit
        #[inline(always)]
        pub fn ready(&self) -> bool {
            ((self.0 >> 0) & 1) != 0
        }
        /// Status valid bit
        #[inline(always)]
        pub fn valid(&self) -> bool {
            ((self.0 >> 1) & 1) != 0
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
        DoeClearSecrets = 3,
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
        pub fn doe_clear_secrets(&self) -> bool {
            *self == Self::DoeClearSecrets
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
                3 => Ok(Self::DoeClearSecrets),
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
            pub fn doe_clear_secrets(&self) -> super::DoeCmdE {
                super::DoeCmdE::DoeClearSecrets
            }
        }
    }
}
pub mod meta {
    //! Additional metadata needed by ureg.
    #[derive(Clone, Copy)]
    pub struct Iv();
    impl ureg::RegType for Iv {
        type Raw = u32;
    }
    impl ureg::ReadableReg for Iv {
        type ReadVal = u32;
    }
    impl ureg::WritableReg for Iv {
        type WriteVal = u32;
    }
    impl ureg::ResettableReg for Iv {
        const RESET_VAL: Self::Raw = 0;
    }
    #[derive(Clone, Copy)]
    pub struct Ctrl();
    impl ureg::RegType for Ctrl {
        type Raw = u32;
    }
    impl ureg::ReadableReg for Ctrl {
        type ReadVal = crate::doe::regs::CtrlReadVal;
    }
    impl ureg::WritableReg for Ctrl {
        type WriteVal = crate::doe::regs::CtrlWriteVal;
    }
    impl ureg::ResettableReg for Ctrl {
        const RESET_VAL: Self::Raw = 0;
    }
    #[derive(Clone, Copy)]
    pub struct Status();
    impl ureg::RegType for Status {
        type Raw = u32;
    }
    impl ureg::ReadableReg for Status {
        type ReadVal = crate::doe::regs::StatusReadVal;
    }
}