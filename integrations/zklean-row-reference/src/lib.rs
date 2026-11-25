//! Native SHA-256 reference for an original bounded Horn proof-DAG relation.
//! This is not a Nova circuit or a zero-knowledge proof.
use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

fn digest(tag: &[u8], parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    h.update(tag);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn empty() -> Hash {
    digest(b"ZKL/empty/v1", &[])
}

pub fn leaf(index: u32, atom: u32) -> Hash {
    digest(b"ZKL/row/v1", &[&index.to_be_bytes(), &atom.to_be_bytes()])
}

pub fn parent(left: Hash, right: Hash) -> Hash {
    digest(b"ZKL/node/v1", &[&left, &right])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub head: u32,
    pub premises: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Environment,
    State,
    Rule,
    Arity,
    Path,
    Premise,
    Append,
    Final,
}

#[derive(Debug, Clone)]
pub struct Environment {
    rules: Vec<Rule>,
    goal: u32,
    depth: u32,
    commitment: Hash,
}

impl Environment {
    pub fn new(n: u32, rules: Vec<Rule>, goal: u32, depth: u32) -> Result<Self, Error> {
        if n == 0 || goal >= n || !(1..=20).contains(&depth) {
            return Err(Error::Environment);
        }
        let nr = u32::try_from(rules.len()).map_err(|_| Error::Environment)?;
        let mut h = Sha256::new();
        h.update(b"ZKL/env/v1");
        for v in [n, goal, depth, nr] {
            h.update(v.to_be_bytes());
        }
        for rule in &rules {
            if rule.head >= n || rule.premises.len() > 2 || rule.premises.iter().any(|a| *a >= n) {
                return Err(Error::Environment);
            }
            h.update(rule.head.to_be_bytes());
            h.update((rule.premises.len() as u32).to_be_bytes());
            for a in &rule.premises {
                h.update(a.to_be_bytes());
            }
        }
        Ok(Self { rules, goal, depth, commitment: h.finalize().into() })
    }

    pub fn commitment(&self) -> Hash { self.commitment }

    pub fn initial(&self) -> State {
        let mut root = empty();
        for _ in 0..self.depth {
            root = parent(root, root);
        }
        State { env: self.commitment, root, count: 0, last: None, closed: false }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    env: Hash,
    root: Hash,
    count: u32,
    last: Option<u32>,
    closed: bool,
}

impl State {
    pub fn root(&self) -> Hash { self.root }
    pub fn count(&self) -> u32 { self.count }
    pub fn closed(&self) -> bool { self.closed }
}

pub struct Premise<'a> {
    pub index: u32,
    pub path: &'a [Hash],
}

fn root_from(mut value: Hash, index: u32, path: &[Hash], depth: u32) -> Result<Hash, Error> {
    if path.len() != depth as usize || index >= (1u32 << depth) {
        return Err(Error::Path);
    }
    for (level, sibling) in path.iter().enumerate() {
        value = if (index >> level) & 1 == 1 {
            parent(*sibling, value)
        } else {
            parent(value, *sibling)
        };
    }
    Ok(value)
}

/// Verifies one step against a state reached from Environment::initial().
/// Future IVC must constrain the same initial state, rule membership, index
/// bounds, all Merkle paths, and the final state. Native checks alone are not ZK.
pub fn step(
    env: &Environment,
    state: &State,
    rid: u32,
    refs: &[Premise<'_>],
    append_path: &[Hash],
) -> Result<State, Error> {
    if state.env != env.commitment || state.closed || state.count >= (1u32 << env.depth) {
        return Err(Error::State);
    }
    let rule = env.rules.get(rid as usize).ok_or(Error::Rule)?;
    if refs.len() != rule.premises.len() {
        return Err(Error::Arity);
    }
    for (r, atom) in refs.iter().zip(&rule.premises) {
        if r.index >= state.count || root_from(leaf(r.index, *atom), r.index, r.path, env.depth)? != state.root {
            return Err(Error::Premise);
        }
    }
    if root_from(empty(), state.count, append_path, env.depth)? != state.root {
        return Err(Error::Append);
    }
    let root = root_from(leaf(state.count, rule.head), state.count, append_path, env.depth)?;
    Ok(State { env: state.env, root, count: state.count + 1, last: Some(rule.head), closed: false })
}

pub fn finish(env: &Environment, state: &State) -> Result<State, Error> {
    if state.env != env.commitment || state.closed || state.count == 0 || state.last != Some(env.goal) {
        return Err(Error::Final);
    }
    let mut final_state = state.clone();
    final_state.closed = true;
    Ok(final_state)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(hash: Hash) -> String {
        hash.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join("")
    }

    fn path(leaves: &[Hash], index: usize) -> Vec<Hash> {
        let mut level = leaves.to_vec();
        let mut i = index;
        let mut out = Vec::new();
        while level.len() > 1 {
            out.push(level[i ^ 1]);
            i >>= 1;
            level = level.chunks_exact(2).map(|v| parent(v[0], v[1])).collect();
        }
        out
    }

    fn env(goal: u32) -> Environment {
        Environment::new(3, vec![
            Rule { head: 0, premises: vec![] },
            Rule { head: 1, premises: vec![0] },
            Rule { head: 2, premises: vec![0, 1] },
        ], goal, 3).unwrap()
    }

    #[test]
    fn python_cross_language_vector() {
        let e = env(2);
        let mut leaves = vec![empty(); 8];
        let s = e.initial();
        assert_eq!(hex(e.commitment()), "569d05d1048f299bffc08d68af6b53428dc174422bed3c11265203396a9518e2");
        assert_eq!(hex(s.root()), "8b8fd36bf6a65e66d439eb36b503c79d682538ef27eb25c09163e83ce2f421d7");
        assert_eq!(finish(&e, &s), Err(Error::Final));
        let s = step(&e, &s, 0, &[], &path(&leaves, 0)).unwrap();
        leaves[0] = leaf(0, 0);
        assert_eq!(hex(s.root()), "5df5b679457c8dd8b1d09bc3e3415398cfeb7cecddf8eff4bfcf0149e57a9053");
        let p0 = path(&leaves, 0);
        assert_eq!(step(&e, &s, 1, &[], &path(&leaves, 1)), Err(Error::Arity));
        assert_eq!(step(&env(1), &s, 1, &[Premise { index: 0, path: &p0 }], &path(&leaves, 1)), Err(Error::State));
        assert_eq!(step(&e, &s, 1, &[Premise { index: 1, path: &p0 }], &path(&leaves, 1)), Err(Error::Premise));
        assert_eq!(step(&e, &s, 2, &[Premise { index: 0, path: &p0 }, Premise { index: 0, path: &p0 }], &path(&leaves, 1)), Err(Error::Premise));
        assert_eq!(step(&e, &s, 1, &[Premise { index: 0, path: &p0 }], &path(&leaves, 0)), Err(Error::Append));
        let s = step(&e, &s, 1, &[Premise { index: 0, path: &p0 }], &path(&leaves, 1)).unwrap();
        leaves[1] = leaf(1, 1);
        assert_eq!(hex(s.root()), "f2ead8b9de55e97ebcd61499da5d1ca28fe1ba5d23d10572a9524838ad58d3a9");
        let p0 = path(&leaves, 0);
        let p1 = path(&leaves, 1);
        let s = step(&e, &s, 2, &[Premise { index: 0, path: &p0 }, Premise { index: 1, path: &p1 }], &path(&leaves, 2)).unwrap();
        assert_eq!(hex(s.root()), "ab52957260675f3dbe18b8bbe0285008eea9081652b5c6b99142a030ccb082ae");
        let s = finish(&e, &s).unwrap();
        assert!(s.closed());
        assert_eq!(s.count(), 3);
        assert_eq!(step(&e, &s, 0, &[], &path(&leaves, 3)), Err(Error::State));
    }
}
