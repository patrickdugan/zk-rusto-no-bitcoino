//! Frozen compiler-output pins for synthetic authentication cost fixtures.
//! Generated from26 bounded templates only; no graphs, Script execution or keys.
//! Pins are compiler provenance, NOT independent compiler semantics.
//! Baseline provenance normalizes CRLF to LF.
//! Baseline script.py: 3a16a7f87abff5a486953b7a679019370a24815eafab87834ff97c77a3581550
//! Baseline trace.py: 00f3670628687ae4f97c777f7e6c1b1c978ad2516910e987047fb23f42265b78
//! Baseline compact.py: e769fc738d68fde15dc3894517195c2ac54f90bb859e7dd0125bf57d3ff05740
//! Baseline trace_kernels.py: 794929ff94ed7fdd8b4dbb8855846d34430d81e38e82a470b135418ff8d3881f
//! Baseline convolution.py: a898b6ed04f71a1112148069cad309542d991b5524b460c718e9e3fe1a1c41cd
//! Baseline byte_kernels.py: 4896adac75c2063600be1f7f795baa144d249269cb33a3fb352a3ee62f0cf4ea
//! Baseline wots_graph.py: 375fbf04d576a55401fee83404f9fe323c380b83cf3a7ecdaca7983c90c0141e
//! Baseline byte_keccak_round.py: a98c328fe6ecc95404e252fa0c2bf6949973f6d9fab10e30fc29933e31f5537a

use bitvm2_nova_script_oracle::wots::Result;

struct Pin {
    role: &'static str,
    kind: &'static str,
    args: &'static [i64],
    aliases: &'static [usize],
    sha256: &'static str,
}

/// Compiler-output pin only. Independently establish the exact closed source,
/// formal bounds and arithmetic relation before accepting this lookup.
pub fn expected_body_sha256(
    role: &str,
    kind: &str,
    args: &[i64],
    aliases: &[usize],
) -> Result<&'static str> {
    if aliases.is_empty() || aliases.len() > 3 {
        return Err("cost body formal arity exceeds the closed inventory".into());
    }
    let mut next = 0;
    for alias in aliases {
        if *alias > next {
            return Err("cost aliases need first-occurrence normalization".into());
        }
        if *alias == next {
            next += 1;
        }
    }
    PINS.iter()
        .find(|p| p.role == role && p.kind == kind && p.args == args && p.aliases == aliases)
        .map(|p| p.sha256)
        .ok_or_else(|| "unlisted authentication-cost body shape".into())
}

pub fn check(
    role: &str,
    kind: &str,
    args: &[i64],
    wires: &[usize],
    body_sha256: &str,
) -> Result<()> {
    if wires.is_empty() || wires.len() > 3 {
        return Err("cost body occurrence count exceeds the closed inventory".into());
    }
    let mut unique = Vec::new();
    let mut aliases = Vec::new();
    for wire in wires {
        let index = if let Some(i) = unique.iter().position(|w| w == wire) {
            i
        } else {
            unique.push(*wire);
            unique.len() - 1
        };
        aliases.push(index);
    }
    if expected_body_sha256(role, kind, args, &aliases)? != body_sha256 {
        return Err("cost predicate body differs from the frozen compiler pin".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inventory_is_closed_unique_and_canonical_without_keys_or_script() {
        assert_eq!(PIN_COUNT, 26);
        assert_eq!(PINS.len(), PIN_COUNT);
        let mut seen = std::collections::HashSet::new();
        for pin in PINS {
            assert!(seen.insert((pin.role, pin.kind, pin.args, pin.aliases)));
            assert_eq!(pin.sha256.len(), 64);
            assert!(pin
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
            assert_eq!(
                expected_body_sha256(pin.role, pin.kind, pin.args, pin.aliases).unwrap(),
                pin.sha256
            );
            let wires: Vec<_> = pin.aliases.iter().map(|a| 100 + 17 * a).collect();
            assert!(check(pin.role, pin.kind, pin.args, &wires, pin.sha256).is_ok());
            assert!(check(pin.role, pin.kind, pin.args, &wires, &"00".repeat(32)).is_err());
        }
    }
    #[test]
    fn wrong_roles_masks_rotations_and_alias_partitions_reject() {
        for role in ["pallas_scalar", "vesta_scalar"] {
            assert!(expected_body_sha256(role, "conv_ab", &[1], &[0, 1, 2]).is_err());
            assert!(expected_body_sha256(role, "conv_reconstruct", &[8], &[0, 0]).is_err());
            assert!(expected_body_sha256(role, "byte_xor", &[], &[0, 0, 1]).is_err());
            assert!(expected_body_sha256(role, "byte_rol", &[0], &[0, 1, 2]).is_err());
            assert!(expected_body_sha256(role, "byte_xor_const", &[128], &[0, 1]).is_err());
            assert!(expected_body_sha256(role, "byte_not", &[], &[1, 0]).is_err());
        }
        assert!(expected_body_sha256("pallas_base", "byte_not", &[], &[0, 1]).is_err());
    }
}

pub const PIN_COUNT: usize = 26;
static PINS: &[Pin] = &[
    Pin {
        role: "pallas_scalar",
        kind: "byte_and",
        args: &[],
        aliases: &[0, 1, 2],
        sha256: "919dd0ee0e0114572bfd1edb754c1fa4019d2d167b814ec4b37f57ec9c17588e",
    },
    Pin {
        role: "pallas_scalar",
        kind: "byte_not",
        args: &[],
        aliases: &[0, 1],
        sha256: "49281c65c5745f7bfb943bbc883cec722df02f7f2e54c734feb74ddd215111ba",
    },
    Pin {
        role: "pallas_scalar",
        kind: "byte_rol",
        args: &[1],
        aliases: &[0, 1, 2],
        sha256: "cd5e3c5312ce7e09471cbe7046dd1403c8c748dfdb339bbf5871238a191736a3",
    },
    Pin {
        role: "pallas_scalar",
        kind: "byte_rol",
        args: &[2],
        aliases: &[0, 1, 2],
        sha256: "e3d9b8135933f25d21af375e3aa2c51df439d46d5324e6868cb7a044ca23db7f",
    },
    Pin {
        role: "pallas_scalar",
        kind: "byte_rol",
        args: &[3],
        aliases: &[0, 1, 2],
        sha256: "f2582bdfd6af5102d6207637b024bfd26f5365fc07eecaf9b60f7551b1c236aa",
    },
    Pin {
        role: "pallas_scalar",
        kind: "byte_rol",
        args: &[4],
        aliases: &[0, 1, 2],
        sha256: "27449f666338222bb8c1c387f0b4b929e89b4c28041f75b584ad212a75bba8ae",
    },
    Pin {
        role: "pallas_scalar",
        kind: "byte_rol",
        args: &[5],
        aliases: &[0, 1, 2],
        sha256: "4e47d1767e023d7c3293afe0e67415a201e67004b78641d7448dba14a1ca263b",
    },
    Pin {
        role: "pallas_scalar",
        kind: "byte_rol",
        args: &[6],
        aliases: &[0, 1, 2],
        sha256: "9ade59bc68ceba7fa5b4e694c849cd96f66cede0eefdb2c7f7ca0ebf80505177",
    },
    Pin {
        role: "pallas_scalar",
        kind: "byte_rol",
        args: &[7],
        aliases: &[0, 1, 2],
        sha256: "9e41f5a937e1055d0d1aca3f42785acc942624262cc5e6ef3be4fec061c69c45",
    },
    Pin {
        role: "pallas_scalar",
        kind: "byte_xor",
        args: &[],
        aliases: &[0, 1, 2],
        sha256: "b4a544526deaf3557478650e8fa05f05b4118116071cf83e9d14553cca5a8e95",
    },
    Pin {
        role: "pallas_scalar",
        kind: "byte_xor_const",
        args: &[1],
        aliases: &[0, 1],
        sha256: "700a387788d8409796048689ddcddd7af467aab26f7c703b66a9ace21740a730",
    },
    Pin {
        role: "pallas_scalar",
        kind: "conv_ab",
        args: &[1],
        aliases: &[0, 0, 1],
        sha256: "c25ec25c174294eaf532a0bef5cd3308e3832e0f60d36b7ab598e228c0b0b947",
    },
    Pin {
        role: "pallas_scalar",
        kind: "conv_reconstruct",
        args: &[8],
        aliases: &[0, 1],
        sha256: "05ae67c636d88f5ccf8e5b5777cde728602adfba3114d1f62c858a4e7e10e74b",
    },
    Pin {
        role: "vesta_scalar",
        kind: "byte_and",
        args: &[],
        aliases: &[0, 1, 2],
        sha256: "919dd0ee0e0114572bfd1edb754c1fa4019d2d167b814ec4b37f57ec9c17588e",
    },
    Pin {
        role: "vesta_scalar",
        kind: "byte_not",
        args: &[],
        aliases: &[0, 1],
        sha256: "49281c65c5745f7bfb943bbc883cec722df02f7f2e54c734feb74ddd215111ba",
    },
    Pin {
        role: "vesta_scalar",
        kind: "byte_rol",
        args: &[1],
        aliases: &[0, 1, 2],
        sha256: "cd5e3c5312ce7e09471cbe7046dd1403c8c748dfdb339bbf5871238a191736a3",
    },
    Pin {
        role: "vesta_scalar",
        kind: "byte_rol",
        args: &[2],
        aliases: &[0, 1, 2],
        sha256: "e3d9b8135933f25d21af375e3aa2c51df439d46d5324e6868cb7a044ca23db7f",
    },
    Pin {
        role: "vesta_scalar",
        kind: "byte_rol",
        args: &[3],
        aliases: &[0, 1, 2],
        sha256: "f2582bdfd6af5102d6207637b024bfd26f5365fc07eecaf9b60f7551b1c236aa",
    },
    Pin {
        role: "vesta_scalar",
        kind: "byte_rol",
        args: &[4],
        aliases: &[0, 1, 2],
        sha256: "27449f666338222bb8c1c387f0b4b929e89b4c28041f75b584ad212a75bba8ae",
    },
    Pin {
        role: "vesta_scalar",
        kind: "byte_rol",
        args: &[5],
        aliases: &[0, 1, 2],
        sha256: "4e47d1767e023d7c3293afe0e67415a201e67004b78641d7448dba14a1ca263b",
    },
    Pin {
        role: "vesta_scalar",
        kind: "byte_rol",
        args: &[6],
        aliases: &[0, 1, 2],
        sha256: "9ade59bc68ceba7fa5b4e694c849cd96f66cede0eefdb2c7f7ca0ebf80505177",
    },
    Pin {
        role: "vesta_scalar",
        kind: "byte_rol",
        args: &[7],
        aliases: &[0, 1, 2],
        sha256: "9e41f5a937e1055d0d1aca3f42785acc942624262cc5e6ef3be4fec061c69c45",
    },
    Pin {
        role: "vesta_scalar",
        kind: "byte_xor",
        args: &[],
        aliases: &[0, 1, 2],
        sha256: "b4a544526deaf3557478650e8fa05f05b4118116071cf83e9d14553cca5a8e95",
    },
    Pin {
        role: "vesta_scalar",
        kind: "byte_xor_const",
        args: &[1],
        aliases: &[0, 1],
        sha256: "700a387788d8409796048689ddcddd7af467aab26f7c703b66a9ace21740a730",
    },
    Pin {
        role: "vesta_scalar",
        kind: "conv_ab",
        args: &[1],
        aliases: &[0, 0, 1],
        sha256: "c25ec25c174294eaf532a0bef5cd3308e3832e0f60d36b7ab598e228c0b0b947",
    },
    Pin {
        role: "vesta_scalar",
        kind: "conv_reconstruct",
        args: &[8],
        aliases: &[0, 1],
        sha256: "05ae67c636d88f5ccf8e5b5777cde728602adfba3114d1f62c858a4e7e10e74b",
    },
];
