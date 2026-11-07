"""Pin unchanged predicate bodies for the closed synthetic cost experiment.

Only 26 tiny public kind/argument/alias templates are compiled and hashed. No
Program, GraphSpec, Script execution, key generation, proving or full round is
performed. These pins record trusted compiler provenance; the native closed
source checker and independent arithmetic executor must establish semantics.
"""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import re

from script import P, Q
from trace_kernels import compile_predicate
from wots_graph import expansion_script

ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT/'auth-cost-oracle'/'src'/'body_pins.rs'
BASELINE_SOURCES = ('script.py', 'trace.py', 'compact.py', 'trace_kernels.py',
    'convolution.py', 'byte_kernels.py', 'wots_graph.py', 'byte_keccak_round.py')


def templates():
    """The two mixed shapes and eleven unaliased round0 BYTE shapes."""
    yield 'conv_reconstruct', (8,), (0, 1)
    yield 'conv_ab', (1,), (0, 0, 1)
    for kind in ('byte_xor', 'byte_and'):
        yield kind, (), (0, 1, 2)
    yield 'byte_not', (), (0, 1)
    for shift in range(1, 8):
        yield 'byte_rol', (shift,), (0, 1, 2)
    yield 'byte_xor_const', (1,), (0, 1)


RUST_API = r'''
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
pub fn expected_body_sha256(role: &str, kind: &str, args: &[i64], aliases: &[usize])
    -> Result<&'static str>
{
    if aliases.is_empty() || aliases.len() > 3 {
        return Err("cost body formal arity exceeds the closed inventory".into());
    }
    let mut next = 0;
    for alias in aliases {
        if *alias > next {
            return Err("cost aliases need first-occurrence normalization".into());
        }
        if *alias == next { next += 1; }
    }
    PINS.iter().find(|p| p.role == role && p.kind == kind && p.args == args && p.aliases == aliases)
        .map(|p| p.sha256).ok_or_else(|| "unlisted authentication-cost body shape".into())
}

pub fn check(role: &str, kind: &str, args: &[i64], wires: &[usize], body_sha256: &str)
    -> Result<()>
{
    if wires.is_empty() || wires.len() > 3 {
        return Err("cost body occurrence count exceeds the closed inventory".into());
    }
    let mut unique = Vec::new();
    let mut aliases = Vec::new();
    for wire in wires {
        let index = if let Some(i) = unique.iter().position(|w| w == wire) { i }
            else { unique.push(*wire); unique.len()-1 };
        aliases.push(index);
    }
    if expected_body_sha256(role,kind,args,&aliases)? != body_sha256 {
        return Err("cost predicate body differs from the frozen compiler pin".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inventory_is_closed_unique_and_canonical_without_keys_or_script() {
        assert_eq!(PIN_COUNT,26);
        assert_eq!(PINS.len(),PIN_COUNT);
        let mut seen = std::collections::HashSet::new();
        for pin in PINS {
            assert!(seen.insert((pin.role,pin.kind,pin.args,pin.aliases)));
            assert_eq!(pin.sha256.len(),64);
            assert!(pin.sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
            assert_eq!(expected_body_sha256(pin.role,pin.kind,pin.args,pin.aliases).unwrap(),pin.sha256);
            let wires: Vec<_> = pin.aliases.iter().map(|a| 100+17*a).collect();
            assert!(check(pin.role,pin.kind,pin.args,&wires,pin.sha256).is_ok());
            assert!(check(pin.role,pin.kind,pin.args,&wires,&"00".repeat(32)).is_err());
        }
    }
    #[test]
    fn wrong_roles_masks_rotations_and_alias_partitions_reject() {
        for role in ["pallas_scalar","vesta_scalar"] {
            assert!(expected_body_sha256(role,"conv_ab",&[1],&[0,1,2]).is_err());
            assert!(expected_body_sha256(role,"conv_reconstruct",&[8],&[0,0]).is_err());
            assert!(expected_body_sha256(role,"byte_xor",&[],&[0,0,1]).is_err());
            assert!(expected_body_sha256(role,"byte_rol",&[0],&[0,1,2]).is_err());
            assert!(expected_body_sha256(role,"byte_xor_const",&[128],&[0,1]).is_err());
            assert!(expected_body_sha256(role,"byte_not",&[],&[1,0]).is_err());
        }
        assert!(expected_body_sha256("pallas_base","byte_not",&[],&[0,1]).is_err());
    }
}
'''


def generate():
    pins, metrics = [], []
    for role, modulus in (('pallas_scalar', Q), ('vesta_scalar', P)):
        for kind, argument, aliases in templates():
            renamed = tuple(100+17*index for index in aliases)
            expansion = expansion_script(aliases)
            if expansion != expansion_script(renamed):
                raise ValueError('injective wire renaming changed the frozen alias expansion')
            body = expansion+compile_predicate(modulus, kind, argument)
            digest = sha256(body).hexdigest()
            pins.append((role, kind, argument, aliases, digest))
            metrics.append(dict(role=role, kind=kind, argument=argument,
                aliases=aliases, body_bytes=len(body), sha256=digest))
    if len(pins) != 26 or len(set(row[:4] for row in pins)) != 26:
        raise ValueError('closed cost pin inventory must contain exactly26 unique keys')
    sources = {name: sha256((ROOT/name).read_bytes().replace(b'\r\n', b'\n')).hexdigest()
               for name in BASELINE_SOURCES}
    header = ('//! Frozen compiler-output pins for synthetic authentication cost fixtures.\n'
        '//! Generated from26 bounded templates only; no graphs, Script execution or keys.\n'
        '//! Pins are compiler provenance, NOT independent compiler semantics.\n'
        '//! Baseline provenance normalizes CRLF to LF.\n')
    header += ''.join(f'//! Baseline {name}: {digest}\n' for name, digest in sources.items())
    rows = []
    for role, kind, argument, aliases, digest in sorted(pins):
        args = ', '.join(map(str, argument))
        slots = ', '.join(map(str, aliases))
        rows.append(f'    Pin {{ role: "{role}", kind: "{kind}", args: &[{args}], aliases: &[{slots}], sha256: "{digest}" }},')
    result = header+RUST_API+'\npub const PIN_COUNT: usize = 26;\nstatic PINS: &[Pin] = &[\n'+'\n'.join(rows)+'\n];\n'
    return result, dict(pins=26, baseline_sources=sources, bodies=metrics,
        independent_compiler_semantics_verified=False)


def _inventory(text):
    pattern = (r'Pin\s*\{\s*role:\s*"([^"]+)",\s*kind:\s*"([^"]+)",'
        r'\s*args:\s*&\[([^]]*)\],\s*aliases:\s*&\[([^]]*)\],'
        r'\s*sha256:\s*"([0-9a-f]{64})"\s*,?\s*\}')
    rows = tuple((role, kind,
        tuple(int(n.strip()) for n in args.split(',') if n.strip()),
        tuple(int(n.strip()) for n in aliases.split(',') if n.strip()), digest)
        for role, kind, args, aliases, digest in re.findall(pattern, text))
    count = re.search(r'pub const PIN_COUNT:\s*usize\s*=\s*(\d+);', text)
    provenance = re.findall(r'^//! Baseline ([^:]+): ([0-9a-f]{64})$', text, re.M)
    if count is None or int(count.group(1)) != len(rows):
        raise ValueError('static authentication-cost pin count/format differs')
    return rows, provenance


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    text, stats = generate()
    if args.check:
        if _inventory(OUTPUT.read_text(encoding='utf-8')) != _inventory(text):
            raise ValueError('cost body pins or baseline provenance changed')
    else:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(text, encoding='utf-8', newline='\n')
    print(json.dumps(stats, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    main()
