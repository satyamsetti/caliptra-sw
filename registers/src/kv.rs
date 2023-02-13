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
    pub fn kv_reg() -> Self {
        unsafe { Self::new(0x10018000 as *mut u32) }
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
    /// Controls for each keyvault and pcr entry
    ///
    /// Read value: [`kv::regs::KvctrlReadVal`]; Write value: [`kv::regs::KvctrlWriteVal`]
    pub fn pcr_ctrl(&self) -> ureg::Array<8, ureg::RegRef<crate::kv::meta::PcrCtrl, &TMmio>> {
        unsafe {
            ureg::Array::new_with_mmio(
                self.ptr.wrapping_add(0 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
    /// Read value: [`u32`]; Write value: [`u32`]
    pub fn pcr_entry(
        &self,
    ) -> ureg::Array<8, ureg::Array<16, ureg::RegRef<crate::kv::meta::PcrEntry, &TMmio>>> {
        unsafe {
            ureg::Array::new_with_mmio(
                self.ptr.wrapping_add(0x200 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
    /// Controls for each keyvault and pcr entry
    ///
    /// Read value: [`kv::regs::KvctrlReadVal`]; Write value: [`kv::regs::KvctrlWriteVal`]
    pub fn key_ctrl(&self) -> ureg::Array<8, ureg::RegRef<crate::kv::meta::KeyCtrl, &TMmio>> {
        unsafe {
            ureg::Array::new_with_mmio(
                self.ptr.wrapping_add(0x400 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
    /// Key Entries are not readable or writeable by software
    ///
    /// Read value: [`u32`]; Write value: [`u32`]
    pub fn key_entry(
        &self,
    ) -> ureg::Array<8, ureg::Array<16, ureg::RegRef<crate::kv::meta::KeyEntry, &TMmio>>> {
        unsafe {
            ureg::Array::new_with_mmio(
                self.ptr.wrapping_add(0x600 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
    /// Read value: [`kv::regs::ClearSecretsReadVal`]; Write value: [`kv::regs::ClearSecretsWriteVal`]
    pub fn clear_secrets(&self) -> ureg::RegRef<crate::kv::meta::ClearSecrets, &TMmio> {
        unsafe {
            ureg::RegRef::new_with_mmio(
                self.ptr.wrapping_add(0x800 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
    /// Controls for the Sticky Data Vault Entries
    ///
    /// Read value: [`kv::regs::StickydatavaultctrlReadVal`]; Write value: [`kv::regs::StickydatavaultctrlWriteVal`]
    pub fn sticky_data_vault_ctrl(
        &self,
    ) -> ureg::Array<10, ureg::RegRef<crate::kv::meta::Stickydatavaultctrl, &TMmio>> {
        unsafe {
            ureg::Array::new_with_mmio(
                self.ptr.wrapping_add(0x804 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
    /// Controls for the Non-Sticky Data Vault Entries
    ///
    /// Read value: [`kv::regs::StickydatavaultctrlReadVal`]; Write value: [`kv::regs::StickydatavaultctrlWriteVal`]
    pub fn non_sticky_data_vault_ctrl(
        &self,
    ) -> ureg::Array<10, ureg::RegRef<crate::kv::meta::Nonstickydatavaultctrl, &TMmio>> {
        unsafe {
            ureg::Array::new_with_mmio(
                self.ptr.wrapping_add(0x82c / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
    /// Non-Sticky Scratch Register Controls
    ///
    /// Read value: [`kv::regs::StickylockablescratchregctrlReadVal`]; Write value: [`kv::regs::StickylockablescratchregctrlWriteVal`]
    pub fn non_sticky_lockable_scratch_reg_ctrl(
        &self,
    ) -> ureg::Array<10, ureg::RegRef<crate::kv::meta::Nonstickylockablescratchregctrl, &TMmio>>
    {
        unsafe {
            ureg::Array::new_with_mmio(
                self.ptr.wrapping_add(0x854 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
    /// Read value: [`u32`]; Write value: [`u32`]
    pub fn sticky_data_vault_entry(
        &self,
    ) -> ureg::Array<10, ureg::Array<12, ureg::RegRef<crate::kv::meta::StickyDataVaultEntry, &TMmio>>>
    {
        unsafe {
            ureg::Array::new_with_mmio(
                self.ptr.wrapping_add(0x900 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
    /// Read value: [`u32`]; Write value: [`u32`]
    pub fn nonsticky_data_vault_entry(
        &self,
    ) -> ureg::Array<
        10,
        ureg::Array<12, ureg::RegRef<crate::kv::meta::NonstickyDataVaultEntry, &TMmio>>,
    > {
        unsafe {
            ureg::Array::new_with_mmio(
                self.ptr.wrapping_add(0xc00 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
    /// Read value: [`u32`]; Write value: [`u32`]
    pub fn non_sticky_lockable_scratch_reg(
        &self,
    ) -> ureg::Array<10, ureg::RegRef<crate::kv::meta::Nonstickylockablescratchreg, &TMmio>> {
        unsafe {
            ureg::Array::new_with_mmio(
                self.ptr.wrapping_add(0xf00 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
    /// Read value: [`u32`]; Write value: [`u32`]
    pub fn non_sticky_generic_scratch_reg(
        &self,
    ) -> ureg::Array<8, ureg::RegRef<crate::kv::meta::Nonstickygenericscratchreg, &TMmio>> {
        unsafe {
            ureg::Array::new_with_mmio(
                self.ptr.wrapping_add(0xf28 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
    /// Sticky Scratch Register Controls
    ///
    /// Read value: [`kv::regs::StickylockablescratchregctrlReadVal`]; Write value: [`kv::regs::StickylockablescratchregctrlWriteVal`]
    pub fn sticky_lockable_scratch_reg_ctrl(
        &self,
    ) -> ureg::Array<8, ureg::RegRef<crate::kv::meta::Stickylockablescratchregctrl, &TMmio>> {
        unsafe {
            ureg::Array::new_with_mmio(
                self.ptr.wrapping_add(0xf48 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
    /// Read value: [`u32`]; Write value: [`u32`]
    pub fn sticky_lockable_scratch_reg(
        &self,
    ) -> ureg::Array<8, ureg::RegRef<crate::kv::meta::Stickylockablescratchreg, &TMmio>> {
        unsafe {
            ureg::Array::new_with_mmio(
                self.ptr.wrapping_add(0xf68 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
}
pub mod regs {
    //! Types that represent the values held by registers.
    #[derive(Clone, Copy)]
    pub struct ClearSecretsReadVal(u32);
    impl ClearSecretsReadVal {
        /// Fill the keyvault with debug values
        #[inline(always)]
        pub fn wr_debug_values(&self) -> bool {
            ((self.0 >> 0) & 1) != 0
        }
        /// Selects between debug value 0 or 1 parameter to write to keyvault
        #[inline(always)]
        pub fn sel_debug_value(&self) -> bool {
            ((self.0 >> 1) & 1) != 0
        }
        /// Construct a WriteVal that can be used to modify the contents of this register value.
        pub fn modify(self) -> ClearSecretsWriteVal {
            ClearSecretsWriteVal(self.0)
        }
    }
    impl From<u32> for ClearSecretsReadVal {
        fn from(val: u32) -> Self {
            Self(val)
        }
    }
    impl From<ClearSecretsReadVal> for u32 {
        fn from(val: ClearSecretsReadVal) -> u32 {
            val.0
        }
    }
    #[derive(Clone, Copy)]
    pub struct ClearSecretsWriteVal(u32);
    impl ClearSecretsWriteVal {
        /// Fill the keyvault with debug values
        #[inline(always)]
        pub fn wr_debug_values(self, val: bool) -> Self {
            Self((self.0 & !(1 << 0)) | (u32::from(val) << 0))
        }
        /// Selects between debug value 0 or 1 parameter to write to keyvault
        #[inline(always)]
        pub fn sel_debug_value(self, val: bool) -> Self {
            Self((self.0 & !(1 << 1)) | (u32::from(val) << 1))
        }
    }
    impl From<u32> for ClearSecretsWriteVal {
        fn from(val: u32) -> Self {
            Self(val)
        }
    }
    impl From<ClearSecretsWriteVal> for u32 {
        fn from(val: ClearSecretsWriteVal) -> u32 {
            val.0
        }
    }
    #[derive(Clone, Copy)]
    pub struct StickydatavaultctrlReadVal(u32);
    impl StickydatavaultctrlReadVal {
        /// Lock writes to this entry. Writes will be suppressed when locked.
        #[inline(always)]
        pub fn lock_entry(&self) -> bool {
            ((self.0 >> 0) & 1) != 0
        }
        /// Construct a WriteVal that can be used to modify the contents of this register value.
        pub fn modify(self) -> StickydatavaultctrlWriteVal {
            StickydatavaultctrlWriteVal(self.0)
        }
    }
    impl From<u32> for StickydatavaultctrlReadVal {
        fn from(val: u32) -> Self {
            Self(val)
        }
    }
    impl From<StickydatavaultctrlReadVal> for u32 {
        fn from(val: StickydatavaultctrlReadVal) -> u32 {
            val.0
        }
    }
    #[derive(Clone, Copy)]
    pub struct StickydatavaultctrlWriteVal(u32);
    impl StickydatavaultctrlWriteVal {
        /// Lock writes to this entry. Writes will be suppressed when locked.
        #[inline(always)]
        pub fn lock_entry(self, val: bool) -> Self {
            Self((self.0 & !(1 << 0)) | (u32::from(val) << 0))
        }
    }
    impl From<u32> for StickydatavaultctrlWriteVal {
        fn from(val: u32) -> Self {
            Self(val)
        }
    }
    impl From<StickydatavaultctrlWriteVal> for u32 {
        fn from(val: StickydatavaultctrlWriteVal) -> u32 {
            val.0
        }
    }
    #[derive(Clone, Copy)]
    pub struct StickylockablescratchregctrlReadVal(u32);
    impl StickylockablescratchregctrlReadVal {
        /// Lock writes to the Scratch registers. Writes will be suppressed when locked.
        #[inline(always)]
        pub fn lock_entry(&self) -> bool {
            ((self.0 >> 0) & 1) != 0
        }
        /// Construct a WriteVal that can be used to modify the contents of this register value.
        pub fn modify(self) -> StickylockablescratchregctrlWriteVal {
            StickylockablescratchregctrlWriteVal(self.0)
        }
    }
    impl From<u32> for StickylockablescratchregctrlReadVal {
        fn from(val: u32) -> Self {
            Self(val)
        }
    }
    impl From<StickylockablescratchregctrlReadVal> for u32 {
        fn from(val: StickylockablescratchregctrlReadVal) -> u32 {
            val.0
        }
    }
    #[derive(Clone, Copy)]
    pub struct StickylockablescratchregctrlWriteVal(u32);
    impl StickylockablescratchregctrlWriteVal {
        /// Lock writes to the Scratch registers. Writes will be suppressed when locked.
        #[inline(always)]
        pub fn lock_entry(self, val: bool) -> Self {
            Self((self.0 & !(1 << 0)) | (u32::from(val) << 0))
        }
    }
    impl From<u32> for StickylockablescratchregctrlWriteVal {
        fn from(val: u32) -> Self {
            Self(val)
        }
    }
    impl From<StickylockablescratchregctrlWriteVal> for u32 {
        fn from(val: StickylockablescratchregctrlWriteVal) -> u32 {
            val.0
        }
    }
    #[derive(Clone, Copy)]
    pub struct KvctrlReadVal(u32);
    impl KvctrlReadVal {
        /// Lock writes to this entry. Writes will be suppressed and an error will be recorded.
        #[inline(always)]
        pub fn lock_wr(&self) -> bool {
            ((self.0 >> 0) & 1) != 0
        }
        /// Lock use of this entry. Reads will be suppressed and an error will be recorded.
        #[inline(always)]
        pub fn lock_use(&self) -> bool {
            ((self.0 >> 1) & 1) != 0
        }
        /// Clear the data stored in this entry. Lock write will prevent this clear.
        #[inline(always)]
        pub fn clear(&self) -> bool {
            ((self.0 >> 2) & 1) != 0
        }
        /// Reserved
        #[inline(always)]
        pub fn rsvd0(&self) -> bool {
            ((self.0 >> 3) & 1) != 0
        }
        /// Reserved
        #[inline(always)]
        pub fn rsvd1(&self) -> u32 {
            (self.0 >> 4) & 0xf
        }
        /// Destination valid bits stored as an array for ease of use in RTL.
        ///
        /// dest_valid[0] = hmac_key_dest_valid
        ///
        /// dest_valid[1] = hmac_block_dest_valid
        ///
        /// dest_valid[2] = sha_block_dest_valid
        ///
        /// dest_valid[3] = ecc_pkey_dest_valid
        ///
        /// dest_valid[4] = ecc_seed_dest_valid
        ///
        /// dest_valid[5] = ecc_msg_dest_valid
        #[inline(always)]
        pub fn dest_valid(&self) -> u32 {
            (self.0 >> 8) & 0x3f
        }
        /// Reserved bits
        #[inline(always)]
        pub fn rsvd(&self) -> u32 {
            (self.0 >> 14) & 0x3ffff
        }
        /// Construct a WriteVal that can be used to modify the contents of this register value.
        pub fn modify(self) -> KvctrlWriteVal {
            KvctrlWriteVal(self.0)
        }
    }
    impl From<u32> for KvctrlReadVal {
        fn from(val: u32) -> Self {
            Self(val)
        }
    }
    impl From<KvctrlReadVal> for u32 {
        fn from(val: KvctrlReadVal) -> u32 {
            val.0
        }
    }
    #[derive(Clone, Copy)]
    pub struct KvctrlWriteVal(u32);
    impl KvctrlWriteVal {
        /// Lock writes to this entry. Writes will be suppressed and an error will be recorded.
        #[inline(always)]
        pub fn lock_wr(self, val: bool) -> Self {
            Self((self.0 & !(1 << 0)) | (u32::from(val) << 0))
        }
        /// Lock use of this entry. Reads will be suppressed and an error will be recorded.
        #[inline(always)]
        pub fn lock_use(self, val: bool) -> Self {
            Self((self.0 & !(1 << 1)) | (u32::from(val) << 1))
        }
        /// Clear the data stored in this entry. Lock write will prevent this clear.
        #[inline(always)]
        pub fn clear(self, val: bool) -> Self {
            Self((self.0 & !(1 << 2)) | (u32::from(val) << 2))
        }
        /// Reserved
        #[inline(always)]
        pub fn rsvd0(self, val: bool) -> Self {
            Self((self.0 & !(1 << 3)) | (u32::from(val) << 3))
        }
        /// Reserved
        #[inline(always)]
        pub fn rsvd1(self, val: u32) -> Self {
            Self((self.0 & !(0xf << 4)) | ((val & 0xf) << 4))
        }
        /// Reserved bits
        #[inline(always)]
        pub fn rsvd(self, val: u32) -> Self {
            Self((self.0 & !(0x3ffff << 14)) | ((val & 0x3ffff) << 14))
        }
    }
    impl From<u32> for KvctrlWriteVal {
        fn from(val: u32) -> Self {
            Self(val)
        }
    }
    impl From<KvctrlWriteVal> for u32 {
        fn from(val: KvctrlWriteVal) -> u32 {
            val.0
        }
    }
}
pub mod enums {
    //! Enumerations used by some register fields.
    pub mod selector {}
}
pub mod meta {
    //! Additional metadata needed by ureg.
    pub type PcrCtrl =
        ureg::ReadWriteReg32<0, crate::kv::regs::KvctrlReadVal, crate::kv::regs::KvctrlWriteVal>;
    pub type PcrEntry = ureg::ReadWriteReg32<0, u32, u32>;
    pub type KeyCtrl =
        ureg::ReadWriteReg32<0, crate::kv::regs::KvctrlReadVal, crate::kv::regs::KvctrlWriteVal>;
    pub type KeyEntry = ureg::WriteOnlyReg32<0, u32>;
    pub type ClearSecrets = ureg::ReadWriteReg32<
        0,
        crate::kv::regs::ClearSecretsReadVal,
        crate::kv::regs::ClearSecretsWriteVal,
    >;
    pub type Stickydatavaultctrl = ureg::ReadWriteReg32<
        0,
        crate::kv::regs::StickydatavaultctrlReadVal,
        crate::kv::regs::StickydatavaultctrlWriteVal,
    >;
    pub type Nonstickydatavaultctrl = ureg::ReadWriteReg32<
        0,
        crate::kv::regs::StickydatavaultctrlReadVal,
        crate::kv::regs::StickydatavaultctrlWriteVal,
    >;
    pub type Nonstickylockablescratchregctrl = ureg::ReadWriteReg32<
        0,
        crate::kv::regs::StickylockablescratchregctrlReadVal,
        crate::kv::regs::StickylockablescratchregctrlWriteVal,
    >;
    pub type StickyDataVaultEntry = ureg::ReadWriteReg32<0, u32, u32>;
    pub type NonstickyDataVaultEntry = ureg::ReadWriteReg32<0, u32, u32>;
    pub type Nonstickylockablescratchreg = ureg::ReadWriteReg32<0, u32, u32>;
    pub type Nonstickygenericscratchreg = ureg::ReadWriteReg32<0, u32, u32>;
    pub type Stickylockablescratchregctrl = ureg::ReadWriteReg32<
        0,
        crate::kv::regs::StickylockablescratchregctrlReadVal,
        crate::kv::regs::StickylockablescratchregctrlWriteVal,
    >;
    pub type Stickylockablescratchreg = ureg::ReadWriteReg32<0, u32, u32>;
}
