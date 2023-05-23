// Licensed under the Apache-2.0 license

use caliptra_image_gen::{ImageGeneratorOwnerConfig, ImageGeneratorVendorConfig};
use caliptra_image_types::{
    ImageEccPrivKey, ImageEccPubKey, ImageLmsPrivKey, ImageLmsPublicKey, ImageOwnerPrivKeys,
    ImageOwnerPubKeys, ImageVendorPrivKeys, ImageVendorPubKeys,
};

#[cfg(test)]
use std::fs;
#[cfg(test)]
use std::io::Write; // bring trait into scope
#[cfg(test)]
use zerocopy::AsBytes;

/// Generated with
///
/// ```no_run
/// use caliptra_image_openssl;
/// use std::path::PathBuf;
///
/// fn print_public_key(name: &str, path: &str) {
///     let key = caliptra_image_openssl::ecc_pub_key_from_pem(&PathBuf::from(path)).unwrap();
///     println!("pub const {name}_PUBLIC: ImageEccPubKey = {key:#010x?};");
/// }
/// fn print_private_key(name: &str, path: &str) {
///     let key = caliptra_image_openssl::ecc_priv_key_from_pem(&PathBuf::from(path)).unwrap();
///     println!("pub const {name}_PRIVATE: ImageEccPrivKey = {key:#010x?};");
/// }
///
/// print_public_key("VENDOR_KEY_0", "../../target/riscv32imc-unknown-none-elf/firmware/vnd-pub-key-0.pem");
/// print_private_key("VENDOR_KEY_0", "../../target/riscv32imc-unknown-none-elf/firmware/vnd-priv-key-0.pem");
/// print_public_key("VENDOR_KEY_1", "../../target/riscv32imc-unknown-none-elf/firmware/vnd-pub-key-1.pem");
/// print_private_key("VENDOR_KEY_1", "../../target/riscv32imc-unknown-none-elf/firmware/vnd-priv-key-1.pem");
/// print_public_key("VENDOR_KEY_2", "../../target/riscv32imc-unknown-none-elf/firmware/vnd-pub-key-2.pem");
/// print_private_key("VENDOR_KEY_2", "../../target/riscv32imc-unknown-none-elf/firmware/vnd-priv-key-2.pem");
/// print_public_key("VENDOR_KEY_3", "../../target/riscv32imc-unknown-none-elf/firmware/vnd-pub-key-3.pem");
/// print_private_key("VENDOR_KEY_3", "../../target/riscv32imc-unknown-none-elf/firmware/vnd-priv-key-3.pem");
/// print_public_key("OWNER_KEY", "../../target/riscv32imc-unknown-none-elf/firmware/own-pub-key.pem");
/// print_private_key("OWNER_KEY", "../../target/riscv32imc-unknown-none-elf/firmware/own-priv-key.pem");
/// ```
pub const VENDOR_KEY_0_PUBLIC: ImageEccPubKey = ImageEccPubKey {
    x: [
        0xc69fe67f, 0x97ea3e42, 0x21a7a603, 0x6c2e070d, 0x1657327b, 0xc3f1e7c1, 0x8dccb9e4,
        0xffda5c3f, 0x4db0a1c0, 0x567e0973, 0x17bf4484, 0x39696a07,
    ],
    y: [
        0xc126b913, 0x5fc82572, 0x8f1cd403, 0x19109430, 0x994fe3e8, 0x74a8b026, 0xbe14794d,
        0x27789964, 0x7735fde8, 0x328afd84, 0xcd4d4aa8, 0x72d40b42,
    ],
};
pub const VENDOR_KEY_0_PRIVATE: ImageEccPrivKey = [
    0x29f939ea, 0x41746499, 0xd550c6fa, 0x6368b0d7, 0x61e09b4c, 0x75b21922, 0x86f96240, 0x00ea1d99,
    0xace94ba6, 0x7ae89b0e, 0x3f210cf1, 0x9a45b6b5,
];
pub const VENDOR_KEY_1_PUBLIC: ImageEccPubKey = ImageEccPubKey {
    x: [
        0xa6309750, 0xf0a05ddb, 0x956a7f86, 0x2812ec4f, 0xec454e95, 0x3b53dbfb, 0x9eb54140,
        0x15ea7507, 0x084af93c, 0xb7fa33fe, 0x51811ad5, 0xe754232e,
    ],
    y: [
        0xef5a5987, 0x7a0ce0be, 0x2621d2a9, 0x8bf3c5df, 0xaf7b3d6d, 0x97f24183, 0xa4a42038,
        0x58c39b86, 0x272ef548, 0xe572b937, 0x1ecf1994, 0x1b8d4ea7,
    ],
};
pub const VENDOR_KEY_1_PRIVATE: ImageEccPrivKey = [
    0xf2ee427b, 0x4412f46f, 0x8fb020a5, 0xc23b0154, 0xb3fcb201, 0xf93c2ee2, 0x923fd577, 0xf85320bb,
    0x289eb276, 0x2b6b21d3, 0x5cdb3925, 0xa57d5043,
];
pub const VENDOR_KEY_2_PUBLIC: ImageEccPubKey = ImageEccPubKey {
    x: [
        0xa0d25693, 0xc4251e48, 0x185615b0, 0xa6c27f6d, 0xe62c39f5, 0xa9a32f75, 0x9553226a,
        0x4d1926c1, 0x7928910f, 0xb7adc1b6, 0x89996733, 0x10134881,
    ],
    y: [
        0xbbdf72d7, 0x07c08100, 0xd54fcdad, 0xb1567bb0, 0x0522762b, 0x76b8dc4a, 0x846c175a,
        0x3fbd0501, 0x9bdc8118, 0x4be5f33c, 0xbb21b41d, 0x93a8c523,
    ],
};
pub const VENDOR_KEY_2_PRIVATE: ImageEccPrivKey = [
    0xaf72a74c, 0xfbbacc3c, 0x7ad2f9d9, 0xc969d1c9, 0x19c2d803, 0x0a53749a, 0xee730267, 0x7c11a52d,
    0xee63e4c8, 0x0b5c0293, 0x28d35c27, 0x5f959aee,
];
pub const VENDOR_KEY_3_PUBLIC: ImageEccPubKey = ImageEccPubKey {
    x: [
        0x002a82b6, 0x8e03e9a0, 0xfd3b4c14, 0xca2cb3e8, 0x14350a71, 0x0e43956d, 0x21694fb4,
        0xf34485e8, 0xf0e33583, 0xf7ea142d, 0x50e16f8b, 0x0225bb95,
    ],
    y: [
        0x5802641c, 0x7c45a4a2, 0x408e03a6, 0xa4100a92, 0x50fcc468, 0xd238cd0d, 0x449cc3e5,
        0x1abc25e7, 0x0b05c426, 0x843dcd6f, 0x944ef6ff, 0xfa53ec5b,
    ],
};
pub const VENDOR_KEY_3_PRIVATE: ImageEccPrivKey = [
    0xafbdfc7d, 0x36b54629, 0xd12c4cb5, 0x33926c30, 0x20611617, 0x86b50b23, 0x6046ff93, 0x17ea0144,
    0xbc900c70, 0xb8cb36ac, 0x268b8079, 0xe3aeaaaf,
];
pub const VENDOR_LMS_KEY0_PRIVATE: ImageLmsPrivKey = ImageLmsPrivKey {
    tree_type: 0xc000000,
    otstype: 0x7000000,
    id: [
        0xf1, 0xca, 0x45, 0x6d, 0x98, 0x74, 0xae, 0x5e, 0xe6, 0xa7, 0x58, 0x87, 0x6a, 0x35, 0xfb,
        0x98,
    ],
    seed: [
        0x24, 0x54, 0xbe, 0x3c, 0x39, 0x3e, 0x8f, 0xe1, 0xd7, 0x27, 0x00, 0x1a, 0xfe, 0xdb, 0xb7,
        0xde, 0x67, 0xee, 0x33, 0x93, 0xd6, 0x27, 0xeb, 0x7e,
    ],
};
pub const VENDOR_LMS_KEY0_PUBLIC: ImageLmsPublicKey = ImageLmsPublicKey {
    tree_type: 0xc000000,
    otstype: 0x7000000,
    id: [
        0xf1, 0xca, 0x45, 0x6d, 0x98, 0x74, 0xae, 0x5e, 0xe6, 0xa7, 0x58, 0x87, 0x6a, 0x35, 0xfb,
        0x98,
    ],
    digest: [
        0xd8, 0xd7, 0xbb, 0x47, 0x5a, 0x2f, 0x85, 0x32, 0x5e, 0x65, 0xcc, 0x0c, 0xf2, 0xad, 0x21,
        0x15, 0x1d, 0xa0, 0x61, 0xd3, 0x61, 0xaa, 0x68, 0xe0,
    ],
};
pub const VENDOR_LMS_KEY1_PRIVATE: ImageLmsPrivKey = ImageLmsPrivKey {
    tree_type: 0xc000000,
    otstype: 0x7000000,
    id: [
        0x08, 0x29, 0x69, 0x01, 0x58, 0xd2, 0x61, 0x4a, 0xb1, 0x1e, 0x06, 0xa7, 0x5d, 0x40, 0xcb,
        0x4e,
    ],
    seed: [
        0xdc, 0x78, 0x9c, 0x98, 0x8e, 0x56, 0xed, 0xde, 0x07, 0x49, 0x79, 0x93, 0x1e, 0x6c, 0x0b,
        0x9a, 0xea, 0x59, 0x8b, 0x5b, 0xcc, 0x0c, 0x26, 0xd2,
    ],
};
pub const VENDOR_LMS_KEY1_PUBLIC: ImageLmsPublicKey = ImageLmsPublicKey {
    tree_type: 0xc000000,
    otstype: 0x7000000,
    id: [
        0x08, 0x29, 0x69, 0x01, 0x58, 0xd2, 0x61, 0x4a, 0xb1, 0x1e, 0x06, 0xa7, 0x5d, 0x40, 0xcb,
        0x4e,
    ],
    digest: [
        0x65, 0xdf, 0x0c, 0xe9, 0x37, 0x87, 0xf2, 0x15, 0x20, 0x47, 0x27, 0xd2, 0x73, 0xc0, 0x54,
        0x2b, 0x08, 0x73, 0xdf, 0x83, 0xc8, 0x3f, 0x46, 0x5d,
    ],
};
pub const VENDOR_LMS_KEY2_PRIVATE: ImageLmsPrivKey = ImageLmsPrivKey {
    tree_type: 0xc000000,
    otstype: 0x7000000,
    id: [
        0xd1, 0xc5, 0x6b, 0x7c, 0xa3, 0x87, 0xea, 0x77, 0x79, 0x12, 0x91, 0x3f, 0xed, 0xf4, 0x4f,
        0x9a,
    ],
    seed: [
        0xdc, 0x25, 0xf3, 0xc0, 0xa7, 0xc1, 0xcf, 0x6a, 0x57, 0x2d, 0x40, 0x76, 0x92, 0xf8, 0x7c,
        0xfe, 0x96, 0xe0, 0x84, 0xea, 0x36, 0xad, 0x1e, 0xe2,
    ],
};
pub const VENDOR_LMS_KEY2_PUBLIC: ImageLmsPublicKey = ImageLmsPublicKey {
    tree_type: 0xc000000,
    otstype: 0x7000000,
    id: [
        0xd1, 0xc5, 0x6b, 0x7c, 0xa3, 0x87, 0xea, 0x77, 0x79, 0x12, 0x91, 0x3f, 0xed, 0xf4, 0x4f,
        0x9a,
    ],
    digest: [
        0xcc, 0xb7, 0xc4, 0xfe, 0xe5, 0x69, 0x7d, 0x90, 0x71, 0x6b, 0xda, 0xf9, 0xe1, 0x26, 0xce,
        0xe2, 0xa6, 0x76, 0x5c, 0xcb, 0x1b, 0x37, 0x94, 0xcf,
    ],
};
pub const VENDOR_LMS_KEY3_PRIVATE: ImageLmsPrivKey = ImageLmsPrivKey {
    tree_type: 0xc000000,
    otstype: 0x7000000,
    id: [
        0x5f, 0x83, 0x67, 0x67, 0x46, 0x4c, 0x4a, 0x03, 0x01, 0x55, 0x50, 0x32, 0x57, 0x09, 0x5f,
        0x5c,
    ],
    seed: [
        0x56, 0x9b, 0x8d, 0xaa, 0xdf, 0x89, 0x5c, 0x42, 0xf3, 0xdc, 0x8a, 0x75, 0x4e, 0x53, 0x5f,
        0x35, 0x51, 0x0d, 0xac, 0xe5, 0xa4, 0x98, 0x08, 0x50,
    ],
};
pub const VENDOR_LMS_KEY3_PUBLIC: ImageLmsPublicKey = ImageLmsPublicKey {
    tree_type: 0xc000000,
    otstype: 0x7000000,
    id: [
        0x5f, 0x83, 0x67, 0x67, 0x46, 0x4c, 0x4a, 0x03, 0x01, 0x55, 0x50, 0x32, 0x57, 0x09, 0x5f,
        0x5c,
    ],
    digest: [
        0x2c, 0x42, 0x65, 0x69, 0x3f, 0x66, 0x03, 0xcc, 0x73, 0x6b, 0x88, 0xb2, 0x70, 0x50, 0x18,
        0x20, 0x8f, 0xd5, 0xdc, 0x9c, 0x25, 0x1d, 0xff, 0x03,
    ],
};

pub const OWNER_KEY_PUBLIC: ImageEccPubKey = ImageEccPubKey {
    x: [
        0xc6f82e2b, 0xdcf3e157, 0xa162e7f3, 0x3eca35c4, 0x55ea08a9, 0x13811779, 0xb6f2646d,
        0x92c817cd, 0x4094bd1a, 0xdb215f62, 0xcf36f017, 0x012d5aeb,
    ],
    y: [
        0xa4674593, 0x6cb5a379, 0x99b08264, 0x862b2c1c, 0x517f12c6, 0x573e1f94, 0x7142291a,
        0xf9624bd7, 0x2733dcdd, 0xce24ec5e, 0x961c00e3, 0x4372ba17,
    ],
};
pub const OWNER_KEY_PRIVATE: ImageEccPrivKey = [
    0x59fdf849, 0xe39f4256, 0x19342ed2, 0x81d28d3d, 0x45ab3219, 0x5174582c, 0xecb4e9df, 0x9cc2e991,
    0xb75f88fd, 0xfa4bc6a4, 0x6b88340f, 0x05dd8890,
];
pub const VENDOR_PUBLIC_KEYS: ImageVendorPubKeys = ImageVendorPubKeys {
    ecc_pub_keys: [
        VENDOR_KEY_0_PUBLIC,
        VENDOR_KEY_1_PUBLIC,
        VENDOR_KEY_2_PUBLIC,
        VENDOR_KEY_3_PUBLIC,
    ],
    lms_pub_keys: [
        VENDOR_LMS_KEY0_PUBLIC,
        VENDOR_LMS_KEY1_PUBLIC,
        VENDOR_LMS_KEY2_PUBLIC,
        VENDOR_LMS_KEY3_PUBLIC,
    ],
};

pub const VENDOR_PRIVATE_KEYS: ImageVendorPrivKeys = ImageVendorPrivKeys {
    ecc_priv_keys: [
        VENDOR_KEY_0_PRIVATE,
        VENDOR_KEY_1_PRIVATE,
        VENDOR_KEY_2_PRIVATE,
        VENDOR_KEY_3_PRIVATE,
    ],
    lms_priv_keys: [
        VENDOR_LMS_KEY0_PRIVATE,
        VENDOR_LMS_KEY1_PRIVATE,
        VENDOR_LMS_KEY2_PRIVATE,
        VENDOR_LMS_KEY3_PRIVATE,
    ],
};

pub const VENDOR_CONFIG_KEY_0: ImageGeneratorVendorConfig = ImageGeneratorVendorConfig {
    pub_keys: VENDOR_PUBLIC_KEYS,
    ecc_key_idx: 0,
    lms_key_idx: 0,
    priv_keys: Some(VENDOR_PRIVATE_KEYS),
    not_before: [0u8; 15],
    not_after: [0u8; 15],
};

pub const VENDOR_CONFIG_KEY_1: ImageGeneratorVendorConfig = ImageGeneratorVendorConfig {
    ecc_key_idx: 1,
    lms_key_idx: 1,
    ..VENDOR_CONFIG_KEY_0
};

pub const VENDOR_CONFIG_KEY_2: ImageGeneratorVendorConfig = ImageGeneratorVendorConfig {
    ecc_key_idx: 2,
    lms_key_idx: 2,
    ..VENDOR_CONFIG_KEY_0
};

pub const VENDOR_CONFIG_KEY_3: ImageGeneratorVendorConfig = ImageGeneratorVendorConfig {
    ecc_key_idx: 3,
    lms_key_idx: 3,
    ..VENDOR_CONFIG_KEY_0
};

pub const OWNER_CONFIG: ImageGeneratorOwnerConfig = ImageGeneratorOwnerConfig {
    pub_keys: ImageOwnerPubKeys {
        ecc_pub_key: OWNER_KEY_PUBLIC,
    },
    priv_keys: Some(ImageOwnerPrivKeys {
        ecc_priv_key: OWNER_KEY_PRIVATE,
    }),
    not_before: [0u8; 15],
    not_after: [0u8; 15],
};

#[test]
#[ignore]
fn test_write_lms_keys() {
    for i in 0..VENDOR_PRIVATE_KEYS.lms_priv_keys.len() {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(format!(
                "../../target/riscv32imc-unknown-none-elf/firmware/vnd-lms-priv-key-{}.pem",
                i
            ))
            .unwrap();
        file.write_all(VENDOR_PRIVATE_KEYS.lms_priv_keys[i].as_bytes())
            .unwrap();
    }
    for i in 0..VENDOR_PUBLIC_KEYS.lms_pub_keys.len() {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(format!(
                "../../target/riscv32imc-unknown-none-elf/firmware/vnd-lms-pub-key-{}.pem",
                i
            ))
            .unwrap();
        file.write_all(VENDOR_PUBLIC_KEYS.lms_pub_keys[i].as_bytes())
            .unwrap();
    }
}
