// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

use super::*;

fn pci_record() -> hyper_abi::HyperNativeDeviceProfileInfo {
    hyper_abi::HyperNativeDeviceProfileInfo {
        profile: 4,
        interrupt_count: 64,
        resource_count: 5,
        pci_identity: 0x0001_1de4,
        dma_bus_offset: 0x10_0000_0000,
        aperture_size: 0x80_0000,
    }
}

fn bar_record() -> hyper_abi::HyperNativeDeviceResourceInfo {
    hyper_abi::HyperNativeDeviceResourceInfo {
        kind: 0x201,
        flags: 0,
        offset: 0x40_0000,
        length: 0x40_0000,
        bus_address: 0x40_0000,
    }
}

#[test]
fn profile_decoding_distinguishes_bus_metadata_from_mmio_profiles() -> Result<()> {
    let pci = decode_profile(pci_record())?;
    assert_eq!(pci.profile, Profile::PciFunction);
    assert_eq!(pci.interrupt_count, 64);
    for profile in 1..=3 {
        let record = hyper_abi::HyperNativeDeviceProfileInfo {
            profile,
            interrupt_count: 1,
            resource_count: 1,
            pci_identity: 0,
            dma_bus_offset: 0,
            aperture_size: 65536,
        };
        assert!(decode_profile(record).is_ok());
        assert_eq!(
            decode_profile(hyper_abi::HyperNativeDeviceProfileInfo {
                interrupt_count: 0,
                ..record
            })
            .is_ok(),
            profile == 2,
        );
        assert_eq!(
            decode_profile(hyper_abi::HyperNativeDeviceProfileInfo {
                pci_identity: 1,
                ..record
            }),
            Err(Error::InvalidResponse)
        );
    }
    let mut invalid = pci_record();
    for interrupts in [0, 65, u32::MAX] {
        invalid.interrupt_count = interrupts;
        assert_eq!(decode_profile(invalid), Err(Error::InvalidResponse));
    }
    invalid = pci_record();
    invalid.resource_count = 2;
    assert_eq!(decode_profile(invalid), Err(Error::InvalidResponse));
    invalid = pci_record();
    invalid.aperture_size = 65536;
    assert_eq!(decode_profile(invalid), Err(Error::InvalidResponse));
    invalid = pci_record();
    invalid.dma_bus_offset = 1;
    assert_eq!(decode_profile(invalid), Err(Error::InvalidResponse));
    for identity in [0, 0x10000, 0xffffffff] {
        invalid = pci_record();
        invalid.pci_identity = identity;
        assert_eq!(decode_profile(invalid), Err(Error::InvalidResponse));
    }
    Ok(())
}

#[test]
fn resource_decoding_rejects_unknown_flags_bad_bar_geometry_and_host_addresses() -> Result<()> {
    let profile = decode_profile(pci_record())?;
    assert!(decode_resource(profile, bar_record()).is_ok());
    for record in [
        hyper_abi::HyperNativeDeviceResourceInfo {
            flags: 4,
            ..bar_record()
        },
        hyper_abi::HyperNativeDeviceResourceInfo {
            kind: 0x206,
            ..bar_record()
        },
        hyper_abi::HyperNativeDeviceResourceInfo {
            kind: 0x205,
            flags: 1,
            ..bar_record()
        },
        hyper_abi::HyperNativeDeviceResourceInfo {
            length: 0x400001,
            ..bar_record()
        },
        hyper_abi::HyperNativeDeviceResourceInfo {
            offset: u64::MAX,
            ..bar_record()
        },
        hyper_abi::HyperNativeDeviceResourceInfo {
            bus_address: 0x1f00400000,
            ..bar_record()
        },
    ] {
        assert_eq!(
            decode_resource(profile, record),
            Err(Error::InvalidResponse)
        );
    }
    for (kind, offset, length) in [(0x100, 0, 0x10_0000), (0x101, 0x10_0000, 4096)] {
        let record = hyper_abi::HyperNativeDeviceResourceInfo {
            kind,
            flags: 0,
            offset,
            length,
            bus_address: 0,
        };
        assert!(decode_resource(profile, record).is_ok());
        assert_eq!(
            decode_resource(
                profile,
                hyper_abi::HyperNativeDeviceResourceInfo { flags: 1, ..record }
            ),
            Err(Error::InvalidResponse)
        );
        assert_eq!(
            decode_resource(
                profile,
                hyper_abi::HyperNativeDeviceResourceInfo {
                    bus_address: 1,
                    ..record
                }
            ),
            Err(Error::InvalidResponse)
        );
    }
    Ok(())
}
