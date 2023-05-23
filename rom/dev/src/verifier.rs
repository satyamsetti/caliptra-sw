/*++

Licensed under the Apache-2.0 license.

File Name:

    verifier.rs

Abstract:

    Image Verification support routines.

--*/

use caliptra_drivers::*;
use caliptra_error::caliptra_err_def;
use caliptra_image_types::*;
use caliptra_image_verify::ImageVerificationEnv;
use core::ops::Range;

use crate::rom_env::RomEnv;

caliptra_err_def! {
    RomVerifier,
    RomVerifierErr
    {
        // Errors encountered while reading the key from key vault
        InvalidLmsAlgorithmType = 0x01,
        InvalidLmotsAlgorithmType = 0x02,
        UnsupportedImageLmsKeyParam = 0x03,
        UnsupportedImageLmotsNParam = 0x04,
        UnsupportedImageLmotsPParam = 0x05,
    }
}

/// ROM Verification Environemnt
pub(crate) struct RomImageVerificationEnv<'a> {
    pub(crate) sha384: &'a mut Sha384,
    pub(crate) sha384_acc: &'a mut Sha384Acc,
    pub(crate) soc_ifc: &'a mut SocIfc,
    pub(crate) ecc384: &'a mut Ecc384,
    pub(crate) data_vault: &'a mut DataVault,
    pub(crate) pcr_bank: &'a mut PcrBank,
}

impl<'a> ImageVerificationEnv for &mut RomImageVerificationEnv<'a> {
    /// Calculate Digest using SHA-384 Accelerator
    fn sha384_digest(&mut self, offset: u32, len: u32) -> CaliptraResult<ImageDigest> {
        loop {
            if let Some(mut txn) = self.sha384_acc.try_start_operation() {
                let mut digest = Array4x12::default();
                txn.digest(len, offset, false, &mut digest)?;
                return Ok(digest.0);
            }
        }
    }

    /// ECC-384 Verification routine
    fn ecc384_verify(
        &mut self,
        digest: &ImageDigest,
        pub_key: &ImageEccPubKey,
        sig: &ImageEccSignature,
    ) -> CaliptraResult<bool> {
        // TODO: Remove following conversions after refactoring the driver ECC384PubKey
        // for use across targets
        let pub_key = Ecc384PubKey {
            x: pub_key.x.into(),
            y: pub_key.y.into(),
        };

        // TODO: Remove following conversions after refactoring the driver SHA384Digest
        // for use across targets
        let digest: Array4x12 = digest.into();

        // TODO: Remove following conversions after refactoring the driver ECC384Signature
        // for use across targets
        let sig = Ecc384Signature {
            r: sig.r.into(),
            s: sig.s.into(),
        };

        self.ecc384.verify(&pub_key, &digest, &sig)
    }

    fn lms_verify(
        &self,
        _digest: &ImageDigest,
        _pub_key: &ImageLmsPublicKey,
        _sig: &ImageLmsSignature,
    ) -> CaliptraResult<bool> {
        // let mut message = [0u8; SHA384_DIGEST_BYTE_SIZE];
        // for i in 0..digest.len() {
        //     message[i * 4..][..4].copy_from_slice(&digest[i].to_be_bytes());
        // }

        // let q = u32::from_be(sig.q);

        // let tree_type = match lookup_lms_algorithm_type(u32::from_be(sig.tree_type)) {
        //     Some(x) => x,
        //     None => raise_err!(InvalidLmsAlgorithmType),
        // };
        // let ots_type = match lookup_lmots_algorithm_type(u32::from_be(sig.ots_sig.otstype)) {
        //     Some(x) => x,
        //     None => raise_err!(InvalidLmotsAlgorithmType),
        // };
        // let (_, height) = Lms::default().get_lms_parameters(&tree_type)?;
        // if usize::from(height) != IMAGE_LMS_KEY_HEIGHT {
        //     raise_err!(UnsupportedImageLmsKeyParam)
        // }

        // let lmots_type = Lms::default().get_lmots_parameters(&ots_type)?;
        // if usize::from(lmots_type.p) != IMAGE_LMS_OTS_P_PARAM {
        //     raise_err!(UnsupportedImageLmotsPParam)
        // }
        // if usize::from(lmots_type.n) != SHA192_DIGEST_BYTE_SIZE {
        //     raise_err!(UnsupportedImageLmotsNParam)
        // }
        // let lms_public_key: HashValue<SHA192_DIGEST_WORD_SIZE> = HashValue::from(pub_key.digest);
        // let mut y = [Sha192Digest::default(); IMAGE_LMS_OTS_P_PARAM];
        // for (i, val) in y.iter_mut().enumerate().take(IMAGE_LMS_OTS_P_PARAM) {
        //     *val = Sha192Digest::from(sig.ots_sig.sig[i]);
        // }

        // let mut path = [Sha192Digest::default(); IMAGE_LMS_KEY_HEIGHT];
        // for (i, val) in path.iter_mut().enumerate().take(IMAGE_LMS_KEY_HEIGHT) {
        //     *val = Sha192Digest::from(sig.tree_path[i]);
        // }

        // let mut nonce = [0u32; SHA192_DIGEST_WORD_SIZE];
        // for (i, val) in nonce.iter_mut().enumerate().take(SHA192_DIGEST_WORD_SIZE) {
        //     *val = u32::from_be_bytes([
        //         sig.ots_sig.random[i * 4],
        //         sig.ots_sig.random[i * 4 + 1],
        //         sig.ots_sig.random[i * 4 + 2],
        //         sig.ots_sig.random[i * 4 + 3],
        //     ]);
        // }

        // let ots = LmotsSignature {
        //     ots_type: LmotsAlgorithmType::LmotsSha256N24W4,
        //     nonce,
        //     y,
        // };

        // let lms_sig_val = LmsSignature {
        //     q,
        //     lmots_signature: ots,
        //     sig_type: tree_type,
        //     lms_path: &path,
        // };
        // Lms::default().verify_lms_signature(&message, &pub_key.id, q, &lms_public_key, &lms_sig_val)
        Ok(true)
    }

    /// Retrieve Vendor Public Key Digest
    fn vendor_pub_key_digest(&self) -> ImageDigest {
        self.soc_ifc.fuse_bank().vendor_pub_key_hash().into()
    }

    /// Retrieve Vendor Public Key Revocation Bitmask
    fn vendor_pub_key_revocation(&self) -> VendorPubKeyRevocation {
        self.soc_ifc.fuse_bank().vendor_pub_key_revocation()
    }

    /// Retrieve Owner Public Key Digest from fuses
    fn owner_pub_key_digest_fuses(&self) -> ImageDigest {
        self.soc_ifc.fuse_bank().owner_pub_key_hash().into()
    }

    /// Retrieve Anti-Rollback disable fuse value
    fn anti_rollback_disable(&self) -> bool {
        self.soc_ifc.fuse_bank().anti_rollback_disable()
    }

    /// Retrieve Device Lifecycle state
    fn dev_lifecycle(&self) -> Lifecycle {
        self.soc_ifc.lifecycle()
    }

    /// Get the vendor key index saved in data vault on cold boot
    fn vendor_pub_key_idx_dv(&self) -> u32 {
        self.data_vault.vendor_pk_index()
    }

    /// Get the owner public key digest saved in the dv on cold boot
    fn owner_pub_key_digest_dv(&self) -> ImageDigest {
        self.data_vault.owner_pk_hash().into()
    }

    // Get the fmc digest from the data vault on cold boot
    fn get_fmc_digest_dv(&self) -> ImageDigest {
        self.data_vault.fmc_tci().into()
    }

    // Get Fuse FMC Key Manifest SVN
    fn fmc_svn(&self) -> u32 {
        self.soc_ifc.fuse_bank().fmc_svn()
    }

    // Get Runtime fuse SVN
    fn runtime_svn(&self) -> u32 {
        self.soc_ifc.fuse_bank().runtime_svn()
    }

    fn iccm_range(&self) -> Range<u32> {
        RomEnv::ICCM_RANGE
    }
}
