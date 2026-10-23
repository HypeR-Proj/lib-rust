// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn policy_records_round_trip_without_inactive_fields() -> Result<()> {
    for policy in [
        Policy::Fair {
            weight: 16,
            quantum_ns: 5_000_000,
            backend: FairBackend::Stride,
        },
        Policy::Budget {
            budget_ns: 14_000_000,
            period_ns: 20_000_000,
            burst_ns: 10_000_000,
        },
        Policy::Fifo { priority: 32 },
    ] {
        let parameters = Parameters {
            policy,
            band: 64,
            role: Role::Priority,
        };
        let raw = parameters.encode()?;
        assert_eq!(Parameters::decode(raw)?, parameters);
        let mut reserved = raw;
        reserved.reserved = 1;
        assert!(Parameters::decode(reserved).is_err());
    }
    Ok(())
}

#[test]
fn malformed_kernel_parameters_do_not_truncate_or_accept_hidden_fields() -> Result<()> {
    let p = Parameters {
        policy: Policy::Fifo { priority: 32 },
        band: 64,
        role: Role::Priority,
    };
    let raw = p.encode()?;
    let mut bad = raw;
    bad.band = 256_u32.to_le();
    assert!(Parameters::decode(bad).is_err());
    bad = raw;
    bad.weight = 1;
    assert!(Parameters::decode(bad).is_err());
    bad = raw;
    bad.role = 3;
    assert!(Parameters::decode(bad).is_err());
    Ok(())
}

#[test]
fn invalid_configuration_is_rejected_before_invocation() {
    for policy in [
        Policy::Fair {
            weight: 0,
            quantum_ns: 1,
            backend: FairBackend::Default,
        },
        Policy::Fair {
            weight: 1025,
            quantum_ns: 1,
            backend: FairBackend::Default,
        },
        Policy::Budget {
            budget_ns: 11,
            period_ns: 10,
            burst_ns: 1,
        },
        Policy::Budget {
            budget_ns: 1,
            period_ns: 10,
            burst_ns: 0,
        },
    ] {
        assert!(
            Parameters {
                policy,
                band: 64,
                role: Role::Priority
            }
            .encode()
            .is_err()
        );
    }
}
