"""Generate static verifier-owned pins for the frozen point predicate compiler.

Only tiny predicate/alias templates are compiled and hashed. No Program or graph
is constructed, no Script is executed, and no key material is generated. This
pins the unchanged trusted legacy compiler; it is not an independent proof of
that compiler's mathematical correctness. The native closed topology determines
the normative role, arguments and first-occurrence alias pattern before lookup.
"""
import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path

from script import P, Q
from trace_kernels import compile_predicate
from wots_graph import expansion_script, field_valid_body

ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT/'point-oracle'/'src'/'body_pins.rs'
BASELINE_SOURCES = ('script.py', 'trace_kernels.py', 'compact.py', 'convolution.py',
                    'wots_graph.py', 'curve_trace.py', 'conditional_point.py')


def normalized_source_bytes(path):
    """Portable compiler provenance only; runtime source snapshots remain raw."""
    return path.read_bytes().replace(b'\r\n', b'\n')


def aliases(wires):
    known = {}
    return tuple(known.setdefault(word, len(known)) for word in wires)


def templates(modulus):
    """Closed public shapes, independent of every point/witness value."""
    for constant in (0, 1, 5, 8192):
        yield 'const', (constant,), (0,)
    for kind, arity in (('point_form', 19), ('dispatch', 48), ('bool_xor', 3),
                        ('bool_and', 3), ('field_valid', 9)):
        yield kind, (), tuple(range(arity))
    yield 'add', (), tuple(range(27))
    yield 'add', (), tuple(range(9))+tuple(range(9))+tuple(range(9, 18))
    # Requested compatibility primitive. The current closed point schedule has
    # no equal leaf; the cursor's exact topology cannot introduce one via a pin.
    yield 'equal', (), tuple(range(18))
    for argument in ((0,), (1,), (3,), (4,), (3, 4)):
        yield 'gate_equal', argument, tuple(range(19))
    for argument in ((3,), (4,)):
        yield 'gate_nonzero', argument, tuple(range(10))
    for argument in ((0,), (1,), (2,), (3, 4)):
        yield 'gate_small_equal', argument, tuple(range(3))
    for width in (5, 2, 7, 4, 1, 6, 3):
        yield 'conv_split', (width,), (0, 1, 2)
    for limb in range(9):
        start, end = 29*limb, min(29*limb+29, 256)
        widths = tuple(min(end, 8*byte+8)-max(start, 8*byte)
                       for byte in range(start//8, (end+7)//8))
        yield 'conv_reconstruct', widths, tuple(range(len(widths)+1))
    modulus_bytes = modulus.to_bytes(32, 'little')
    for column in range(64):
        products = [(i, column-i) for i in range(32) if 0 <= column-i < 32]
        for offset in range(0, len(products), 4):
            pairs = products[offset:offset+4]
            for square in (False, True):
                wires = tuple(word for i, j in pairs
                              for word in (('a', i), ('a' if square else 'b', j)))+(('out',),)
                yield 'conv_ab', (len(pairs),), aliases(wires)
        pq = [(coefficient, column-i) for i, coefficient in enumerate(modulus_bytes)
              if coefficient and 0 <= column-i < 32]
        for offset in range(0, len(pq), 8):
            pairs = pq[offset:offset+8]
            yield 'conv_pq', tuple(coefficient for coefficient, _ in pairs), tuple(range(len(pairs)+1))
        shape = ((len(products)+3)//4, (len(pq)+7)//8, int(column < 32))
        yield 'conv_column', shape, tuple(range(shape[0]+shape[1]+2+shape[2]))


RUST_API = r'''
use bitvm2_nova_script_oracle::wots::Result;

struct Pin {
    role: &'static str,
    kind: &'static str,
    args: &'static [i64],
    aliases: &'static [usize],
    sha256: &'static str,
}

/// Lookup only a verifier-derived first-occurrence alias pattern. This static
/// table pins legacy compiler outputs; the independent native cursor must first
/// establish the exact public topology, roles, arguments, words and bounds.
pub fn expected_body_sha256(
    role: &str,
    kind: &str,
    args: &[i64],
    aliases: &[usize],
) -> Result<&'static str> {
    if aliases.is_empty() || aliases.len() > 64 {
        return Err("point body pin alias arity out of bounds".into());
    }
    let mut next = 0;
    for alias in aliases {
        if *alias > next {
            return Err("point body aliases must use first-occurrence numbering".into());
        }
        if *alias == next {
            next += 1;
        }
    }
    PINS.iter()
        .find(|pin| pin.role == role && pin.kind == kind && pin.args == args && pin.aliases == aliases)
        .map(|pin| pin.sha256)
        .ok_or_else(|| "point predicate public shape has no verifier-owned body pin".into())
}

/// Normalize actual ordered formal occurrences, then reject any changed body.
/// Global word numbers are not authority: the closed cursor derives these
/// occurrences before this comparison and separately enforces exact bounds.
pub fn check(
    role: &str,
    kind: &str,
    args: &[i64],
    wires: &[usize],
    body_sha256: &str,
) -> Result<()> {
    if wires.is_empty() || wires.len() > 64 {
        return Err("point body formal arity out of bounds".into());
    }
    let mut unique = Vec::new();
    let mut aliases = Vec::with_capacity(wires.len());
    for wire in wires {
        let alias = if let Some(position) = unique.iter().position(|word| word == wire) {
            position
        } else {
            unique.push(*wire);
            unique.len() - 1
        };
        aliases.push(alias);
    }
    if expected_body_sha256(role, kind, args, &aliases)? != body_sha256 {
        return Err("actual predicate body differs from the verifier-owned legacy compiler pin".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_inventory_has_unique_keys_and_canonical_hashes_without_crypto() {
        assert_eq!(PINS.len(), PIN_COUNT);
        let mut keys = std::collections::HashSet::new();
        for pin in PINS {
            assert!(keys.insert((pin.role, pin.kind, pin.args, pin.aliases)));
            assert_eq!(pin.sha256.len(), 64);
            assert!(pin.sha256.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
            assert_eq!(expected_body_sha256(pin.role, pin.kind, pin.args, pin.aliases).unwrap(), pin.sha256);
            let wires: Vec<_> = pin.aliases.iter().map(|alias| 1000+17*alias).collect();
            check(pin.role, pin.kind, pin.args, &wires, pin.sha256).unwrap();
            assert!(check(pin.role, pin.kind, pin.args, &wires, &"00".repeat(32)).is_err());
        }
    }

    #[test]
    fn unpinned_roles_arguments_and_aliases_are_rejected() {
        assert!(expected_body_sha256("pallas_scalar", "const", &[0], &[0]).is_err());
        assert!(expected_body_sha256("pallas_base", "const", &[8193], &[0]).is_err());
        assert!(expected_body_sha256("pallas_base", "const", &[0], &[1]).is_err());
        assert!(expected_body_sha256("pallas_base", "const", &[0], &[0, 0]).is_err());
        assert!(expected_body_sha256("pallas_base", "bool_not", &[], &[0, 1]).is_err());
    }
}
'''


def generate():
    pins = {}
    for role, modulus in (('pallas_base', P), ('vesta_base', Q)):
        for kind, argument, occurrences in templates(modulus):
            normalized = aliases(occurrences)
            if normalized != occurrences:
                raise ValueError('template aliases must already be first-occurrence normalized')
            expansion = expansion_script(normalized)
            renamed = tuple(1000+17*value for value in normalized)
            if expansion != expansion_script(renamed):
                raise ValueError('legacy alias expansion changed under injective renaming')
            predicate = (field_valid_body(modulus) if kind == 'field_valid'
                         else compile_predicate(modulus, kind, argument))
            digest = sha256(expansion+predicate).hexdigest()
            key = role, kind, argument, normalized
            if key in pins and pins[key] != digest:
                raise ValueError('same closed public template has inconsistent compiler output')
            pins[key] = digest
    source_hashes = {name: sha256(normalized_source_bytes(ROOT/name)).hexdigest()
                     for name in BASELINE_SOURCES}
    rows = []
    for (role, kind, argument, pattern), digest in sorted(pins.items()):
        args = ', '.join(map(str, argument))
        alias = ', '.join(map(str, pattern))
        rows.append(f'    Pin {{ role: "{role}", kind: "{kind}", args: &[{args}], aliases: &[{alias}], sha256: "{digest}" }},')
    header = ('//! Verifier-owned static legacy point predicate body pins.\n'
        '//! Generated by point_body_pins.py using bounded templates only.\n'
        '//! No graph construction, Script execution, key generation or proving.\n'
        '//! These hashes pin trusted compiler outputs, not independent semantics.\n'
        '//! Baseline source provenance normalizes CRLF to LF; runtime snapshots remain raw.\n')
    header += ''.join(f'//! Baseline {name}: {digest}\n' for name, digest in source_hashes.items())
    text = (header+RUST_API+f'\npub const PIN_COUNT: usize = {len(pins)};\n'
            +'static PINS: &[Pin] = &[\n'+'\n'.join(rows)+'\n];\n')
    return text, dict(pins=len(pins), by_role_kind=dict(sorted(Counter(
        role+'/'+kind for role, kind, _, _ in pins).items())), baseline_sources=source_hashes)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='compare pins without changing the file')
    args = parser.parse_args()
    text, stats = generate()
    if args.check:
        # Compare the complete static inventory and compiler provenance, while
        # allowing rustfmt's line breaks and optional trailing commas. The Rust
        # lookup API is separately source-reviewed and tested in hosted CI.
        import re
        existing = OUTPUT.read_text(encoding='utf-8')
        def inventory(value):
            pattern = (r'Pin\s*\{\s*role:\s*"([^"]+)",\s*kind:\s*"([^"]+)",'
                r'\s*args:\s*&\[([^]]*)\],\s*aliases:\s*&\[([^]]*)\],'
                r'\s*sha256:\s*"([0-9a-f]{64})"\s*,?\s*\}')
            records = re.findall(pattern, value)
            count = re.search(r'pub const PIN_COUNT:\s*usize\s*=\s*(\d+);', value)
            sources = re.findall(r'^//! Baseline ([^:]+): ([0-9a-f]{64})$', value, re.M)
            rows = tuple((role, kind,
                tuple(int(n.strip()) for n in args.split(',') if n.strip()),
                tuple(int(n.strip()) for n in alias.split(',') if n.strip()), digest)
                for role, kind, args, alias, digest in records)
            if count is None or int(count.group(1)) != len(rows):
                raise ValueError('static point body pin count/format differs')
            return rows, sources
        if inventory(existing) != inventory(text):
            raise ValueError('generated body pins differ; regenerate and review compiler/source changes')
    else:
        OUTPUT.write_text(text, encoding='utf-8', newline='\n')
    print(json.dumps(stats, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    main()
