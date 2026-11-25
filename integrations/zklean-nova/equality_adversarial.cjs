// ZKL-NOVA-17: independent adversarial checks of the Eq/J native relation.
// This file deliberately constructs its own term DAGs and source notation.
// Local conversion tests concern untyped, locally closed syntax; the separate
// source tests require complete typing certificates and reference acceptance.
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const {Relation, Builder, reference, replay, environment} = require("./equality.cjs");

const S = u => ["S", u], C = i => ["C", i], B = i => ["B", i], F = i => ["F", i];
const A = (f, a) => ["A", f, a], P = (a, b) => ["P", a, b], L = (a, b) => ["L", a, b];
const app = (head, ...args) => args.reduce(A, head);
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const Nat = C(0), zero = C(1), one = A(C(2), zero), functionCarrier = P(Nat, Nat);
const Eq = (carrier, x, y) => app(C(6), carrier, x, y);
const refl = (carrier, x) => app(C(7), carrier, x);
const J = (v, carrier, x, motive, base, y, proof) => app(C(8 + v), carrier, x, motive, base, y, proof);

class Dag {
  constructor() { this.rel = new Relation(); this.terms = new Map(); }
  term(ast) {
    const key = JSON.stringify(ast);
    if (this.terms.has(key)) return this.terms.get(key);
    const row = ["A", "P", "L"].includes(ast[0])
      ? [ast[0], this.term(ast[1]), this.term(ast[2])] : ast.slice();
    const id = this.rel.add(row);
    this.terms.set(key, id);
    return id;
  }
  apply(head, ...args) { return args.reduce((f, a) => this.rel.add(["A", f, a]), head); }
}

function attempt(rel, row) {
  try { rel.add(row); return true; } catch { return false; }
}
function localRule(tag, lhs, rhs) {
  const dag = new Dag(), left = dag.term(lhs), right = dag.term(rhs);
  // Every preceding row has been accepted. Only the selected rule may fail.
  return attempt(dag.rel, [tag, left, right]);
}
function spine(ast) {
  const args = [];
  while (ast[0] === "A") { args.unshift(ast[2]); ast = ast[1]; }
  return {head: ast, args};
}
function locallyClosed(ast, depth = 0) {
  if (ast[0] === "B") return ast[1] < depth;
  if (!["A", "P", "L"].includes(ast[0])) return true;
  return locallyClosed(ast[1], depth) && locallyClosed(ast[2], depth + (ast[0] === "A" ? 0 : 1));
}
function jOracle(lhs, rhs) {
  const {head, args} = spine(lhs);
  if (head[0] !== "C" || ![8, 9, 10].includes(head[1]) || args.length !== 6) return false;
  const [carrier, x, , base, y, proof] = args, p = spine(proof);
  return same(p.head, C(7)) && p.args.length === 2 && same(p.args[0], carrier)
    && same(p.args[1], x) && same(y, x) && same(rhs, base)
    && locallyClosed(lhs) && locallyClosed(rhs);
}

// An independent named syntax keeps proof-index tests legible. It is lowered
// directly to ordinary de Bruijn terms before either checker sees it.
const variable = name => ({variable: name});
const lambda = (name, type, body) => ({binder: "L", name, type, body});
const forall = (name, type, body) => ({binder: "P", name, type, body});
function compile(term, scope = []) {
  if (term.variable) {
    const i = scope.indexOf(term.variable);
    assert(i >= 0, "unknown test variable " + term.variable);
    return B(i);
  }
  if (term.binder) return [term.binder, compile(term.type, scope), compile(term.body, [term.name, ...scope])];
  if (["A", "P", "L"].includes(term[0])) return [term[0], compile(term[1], scope), compile(term[2], scope)];
  return term.slice();
}
function bind(kind, bindings, body) { return bindings.reduceRight((tail, [name, type]) => kind(name, type, tail), body); }
const x = variable("x"), y = variable("y"), h = variable("h"), family = variable("F"), d = variable("d");
const valueMotive = compile(lambda("y", Nat, lambda("h", Eq(Nat, zero, y), Nat)));
const typeMotive = compile(lambda("y", Nat, lambda("h", Eq(Nat, zero, y), S(1))));
const propMotive = compile(lambda("y", Nat, lambda("h", Eq(Nat, zero, y), S(0))));
const equalityMotive = compile(lambda("y", Nat, lambda("h", Eq(Nat, zero, y), Eq(Nat, zero, y))));

function run() {
  const result = {scope: "Native relation and independent reference checks; no cryptographic proof is claimed."};

  // Rebuild the entire spine for each candidate. This explores coordinated
  // changes in carrier, endpoints, recursor, proof and reduct.
  const matrix = {candidates: 0, accepted: 0, rejected: 0, recursor_heads: [3, 6, 7, 8, 9, 10], carrier_choices: 2, endpoint_choices: 3, base_choices: 2};
  for (const head of matrix.recursor_heads)
    for (const carrier of [Nat, functionCarrier])
      for (const proofCarrier of [Nat, functionCarrier])
        for (const source of [zero, one, F(0)])
          for (const proofSource of [zero, one, F(0)])
            for (const dest of [zero, one, F(0)])
              for (const base of [zero, one])
                for (const rhs of [zero, one]) {
                  const lhs = app(C(head), carrier, source, valueMotive, base, dest, refl(proofCarrier, proofSource));
                  const want = jOracle(lhs, rhs), got = localRule("VJ", lhs, rhs);
                  assert.equal(got, want, "VJ matrix " + JSON.stringify([head, carrier, proofCarrier, source, proofSource, dest, base, rhs]));
                  matrix.candidates++; matrix[got ? "accepted" : "rejected"]++;
                }
  assert.equal(matrix.candidates, 2592); assert.equal(matrix.accepted, 36);
  result.coordinated_vj_matrix = matrix;

  const valid = J(1, Nat, zero, valueMotive, zero, zero, refl(Nat, zero));
  const shapeCases = [
    ["non_application", zero, zero, false],
    ["missing_proof_argument", app(C(9), Nat, zero, valueMotive, zero, zero), zero, false],
    ["extra_J_argument", A(valid, zero), zero, false],
    ["missing_refl_endpoint", J(1, Nat, zero, valueMotive, zero, zero, A(C(7), Nat)), zero, false],
    ["extra_refl_argument", J(1, Nat, zero, valueMotive, zero, zero, A(refl(Nat, zero), zero)), zero, false],
    ["bare_refl_constant", J(1, Nat, zero, valueMotive, zero, zero, C(7)), zero, false],
    ["neutral_proof", J(1, Nat, zero, valueMotive, zero, zero, F(0)), zero, false],
    ["neutral_recursor", app(F(0), Nat, zero, valueMotive, zero, zero, refl(Nat, zero)), zero, false],
    ["loose_bound_endpoint", J(1, Nat, B(0), valueMotive, zero, B(0), refl(Nat, B(0))), zero, false],
    ["loose_bound_base", J(1, Nat, zero, valueMotive, B(0), zero, refl(Nat, zero)), B(0), false],
    ["loose_bound_motive", J(1, Nat, zero, B(0), zero, zero, refl(Nat, zero)), zero, false],
    ["closed_bound_variable_in_motive", valid, zero, true],
    ["free_level_endpoint", J(1, Nat, F(0), F(1), F(2), F(0), refl(Nat, F(0))), F(2), true],
    ["beta_wrapper_around_proof", J(1, Nat, zero, valueMotive, zero, zero, A(L(Eq(Nat, zero, zero), B(0)), refl(Nat, zero))), zero, false],
    ["convertible_distinct_destination", J(1, Nat, zero, valueMotive, zero, A(L(Nat, B(0)), zero), refl(Nat, zero)), zero, false]
  ];
  for (const constructor of [0, 1, 2, 3, 4, 5, 6, 8, 9, 10]) shapeCases.push([
    "wrong_constructor_" + constructor,
    J(1, Nat, zero, valueMotive, zero, zero, app(C(constructor), Nat, zero)), zero, false
  ]);
  for (const [name, lhs, rhs, want] of shapeCases) assert.equal(localRule("VJ", lhs, rhs), want, name);
  result.spine_and_scope_cases = shapeCases.map(([name, , , accepted]) => ({name, accepted}));

  // Structural equality does not identify row IDs in this rule. Recreate
  // each correlated argument at a different valid row to verify that bound.
  const aliases = [];
  for (const position of ["carrier", "proof_endpoint", "destination", "reduct"]) {
    const dag = new Dag(), carrier = dag.term(Nat), endpoint = dag.term(zero), motive = dag.term(valueMotive);
    const duplicate = dag.rel.add(["C", position === "carrier" ? 0 : 1]);
    const proof = dag.apply(dag.term(C(7)), position === "carrier" ? duplicate : carrier, position === "proof_endpoint" ? duplicate : endpoint);
    const lhs = dag.apply(dag.term(C(9)), carrier, endpoint, motive, endpoint, position === "destination" ? duplicate : endpoint, proof);
    assert.equal(attempt(dag.rel, ["VJ", lhs, position === "reduct" ? duplicate : endpoint]), false, "duplicate ID " + position);
    aliases.push(position);
  }
  result.distinct_row_id_rejections = aliases;

  const referenceCases = [];
  for (const field of [1, 2]) for (const kind of ["self", "future", "context"]) {
    const dag = new Dag(), lhs = dag.term(valid), rhs = dag.term(zero), context = dag.rel.add(["E"]);
    const row = ["VJ", lhs, rhs];
    row[field] = kind === "context" ? context : dag.rel.rows.length + (kind === "future" ? 1 : 0);
    assert.equal(attempt(dag.rel, row), false, "bad reference " + field + " " + kind);
    referenceCases.push({field, kind});
  }
  result.reference_rejections = referenceCases;

  // The extension must preserve the fixed Nat recursor domain C3..C5.
  const natRules = [];
  for (let head = 0; head < environment.length; head++) {
    const motive = L(Nat, Nat), step = L(Nat, L(Nat, A(C(2), B(0))));
    const at = n => app(C(head), motive, zero, step, n);
    for (const [tag, lhs, rhs] of [["VZ", at(zero), zero], ["VN", at(one), app(step, zero, at(zero))]]) {
      const accepted = head >= 3 && head <= 5;
      assert.equal(localRule(tag, lhs, rhs), accepted, "Nat head " + head + " " + tag);
      natRules.push({tag, head, accepted});
    }
  }
  result.nat_head_domain = natRules;

  const declarationSorts = [2, 1, 1, 0, 2, 3, 2, 0, 0, 2, 3];
  for (let i = 0; i < environment.length; i++) assert(reference(environment[i], S(declarationSorts[i])), "declaration sort " + i);
  function frozen(term) { return Object.isFrozen(term) && term.every(t => !Array.isArray(t) || frozen(t)); }
  assert(frozen(environment), "environment must be recursively immutable");
  const natResult = JSON.parse(fs.readFileSync(path.join(__dirname, "nat_inductive_results.json"), "utf8"));
  assert.deepEqual(environment.slice(0, 6), natResult.environment, "original Nat environment");
  const signatures = {candidates: 0, accepted: 0, rejected: 0};
  for (let constant = 6; constant < 11; constant++) for (let candidate = 0; candidate < 11; candidate++) {
    const dag = new Dag(), ctx = dag.rel.add(["E"]), term = dag.term(C(constant)), ty = dag.term(environment[candidate]);
    const got = attempt(dag.rel, ["JK", ctx, term, ty]), want = same(environment[constant], environment[candidate]);
    assert.equal(got, want, "constant signature " + constant + " " + candidate);
    signatures.candidates++; signatures[got ? "accepted" : "rejected"]++;
  }
  result.environment = {declaration_sorts: declarationSorts, recursively_frozen: true, nat_prefix_unchanged: true, signature_matrix: signatures};

  // Both child terms and both typing premises remain valid. The final JA
  // must reject their incompatible types, even with a fresh output-inst row.
  const applicationCases = [
    ["wrong_refl_endpoint", app(C(9), Nat, zero, valueMotive, zero, zero), refl(Nat, one)],
    ["wrong_destination_proof", app(C(9), Nat, zero, valueMotive, zero, one), refl(Nat, zero)],
    ["wrong_base_type", app(C(9), Nat, zero, valueMotive), S(0)],
    ["wrong_motive_arity", app(C(9), Nat, zero), L(Nat, Nat)],
    ["wrong_motive_universe", app(C(8), Nat, zero), valueMotive],
    ["carrier_above_Sort1", C(7), S(1)],
    ["wrong_source_type", app(C(9), Nat), Nat]
  ];
  for (const [name, fn, arg] of applicationCases) {
    const builder = new Builder(), fnTerm = builder.term(fn), argTerm = builder.term(arg);
    const fj = builder.infer(builder.empty, fnTerm), aj = builder.infer(builder.empty, argTerm);
    const fnType = builder.get(builder.get(fj).ty);
    assert.equal(fnType.tag, "P", name + " setup");
    const inst = builder.inst(fnType.b, 0, argTerm), output = builder.get(inst).out;
    const application = builder.term(A(fn, arg));
    assert.equal(attempt(builder.r, ["JA", builder.empty, application, output, fj, aj, inst]), false, name);
  }
  result.coordinated_typing_premise_rejections = applicationCases.map(([name]) => name);

  const sourceCases = [];
  function source(name, bindings, body, goal, accepted) {
    sourceCases.push({name, proof: compile(bind(lambda, bindings, body)), goal: compile(bind(forall, bindings, goal)), accepted});
  }
  source("reflexivity", [], refl(Nat, zero), Eq(Nat, zero, zero), true);
  const fnIdentity = L(Nat, B(0));
  source("function_carrier", [], refl(functionCarrier, fnIdentity), Eq(functionCarrier, fnIdentity, fnIdentity), true);
  source("proposition_carrier", [], refl(S(0), Eq(Nat, zero, zero)), Eq(S(0), Eq(Nat, zero, zero), Eq(Nat, zero, zero)), true);
  const transportBindings = [["x", Nat], ["y", Nat], ["h", Eq(Nat, x, y)], ["F", forall("z", Nat, S(1))], ["d", A(family, x)]];
  const transportMotive = lambda("z", Nat, lambda("q", Eq(Nat, x, variable("z")), A(family, variable("z"))));
  source("neutral_transport", transportBindings, J(1, Nat, x, transportMotive, d, y, h), A(family, y), true);
  source("transport_requires_eliminator", transportBindings, d, A(family, y), false);
  source("refl_cannot_replace_neutral_path", transportBindings, J(1, Nat, x, transportMotive, d, y, refl(Nat, x)), A(family, y), false);
  const proofFamily = forall("y", Nat, forall("h", Eq(Nat, zero, y), S(1)));
  const proofBindings = [["F", proofFamily], ["d", app(family, zero, refl(Nat, zero))], ["y", Nat], ["h", Eq(Nat, zero, y)]];
  source("proof_dependent_motive", proofBindings, J(1, Nat, zero, family, d, y, h), app(family, y, h), true);
  source("proof_dependent_base_cannot_be_reused", proofBindings, d, app(family, y, h), false);
  source("forced_J2_conversion", [], zero, J(2, Nat, zero, typeMotive, Nat, zero, refl(Nat, zero)), true);
  const betaZero = A(L(Nat, B(0)), zero);
  const betaRefl = A(L(Eq(Nat, zero, zero), B(0)), refl(Nat, zero));
  source("forced_J2_after_beta_conversion", [], zero, J(2, Nat, zero, typeMotive, Nat, betaZero, betaRefl), true);
  const natAtZero = app(C(4), L(Nat, Nat), zero, L(Nat, L(Nat, A(C(2), B(0)))), zero);
  source("forced_J2_after_Nat_conversion", [], zero, J(2, Nat, zero, typeMotive, Nat, natAtZero, refl(Nat, zero)), true);
  source("forced_J1_conversion", [], refl(Nat, zero), J(1, Nat, zero, propMotive, Eq(Nat, zero, zero), zero, refl(Nat, zero)), true);
  const K = variable("K"), u = variable("u"), v = variable("v");
  source("forced_J0_proof_index_conversion", [["K", forall("q", Eq(Nat, zero, zero), S(1))], ["u", A(K, refl(Nat, zero))]], u,
    A(K, J(0, Nat, zero, equalityMotive, refl(Nat, zero), zero, refl(Nat, zero))), true);
  source("distinct_proof_indices", [["u", Eq(Nat, zero, zero)], ["v", Eq(Nat, zero, zero)], ["K", forall("q", Eq(Nat, zero, zero), S(1))], ["d", A(K, u)]], d, A(K, v), false);
  source("wrong_endpoint_goal", [], refl(Nat, zero), Eq(Nat, zero, one), false);
  source("unsupported_carrier_universe", [], refl(S(1), Nat), Eq(S(1), Nat, Nat), false);
  const sourceResults = [];
  for (const test of sourceCases) {
    assert.equal(reference(test.proof, test.goal), test.accepted, "reference " + test.name);
    let rows, nativeAccepted = false;
    try { rows = new Builder().prove(test.proof, test.goal); nativeAccepted = true; } catch {}
    assert.equal(nativeAccepted, test.accepted, "builder " + test.name);
    const detail = {name: test.name, accepted: test.accepted};
    if (rows) {
      const checked = replay(rows, test.goal);
      assert(checked.accepted, "replay " + test.name);
      assert.deepEqual(checked.proof, test.proof, "recovered proof " + test.name);
      detail.rows = rows.length; detail.vj_rows = rows.filter(row => row[0] === "VJ").length;
      if (test.name.startsWith("forced_J")) assert(detail.vj_rows > 0, "forced VJ coverage " + test.name);
      if (test.name === "forced_J2_after_Nat_conversion") {
        detail.vz_rows = rows.filter(row => row[0] === "VZ").length;
        assert(detail.vz_rows > 0, "mixed Nat/J reduction coverage");
      }
    }
    sourceResults.push(detail);
  }
  result.typed_sources = sourceResults;

  const oldFixtures = JSON.parse(fs.readFileSync(path.join(__dirname, "nat_optimized_fixtures.json"), "utf8"));
  result.previous_nat_certificates = oldFixtures.map(fixture => {
    const checked = replay(fixture.rows, fixture.goal);
    assert(checked.accepted, "old Nat certificate " + fixture.name);
    assert.deepEqual(checked.proof, fixture.proof, "old Nat proof " + fixture.name);
    assert(reference(fixture.proof, fixture.goal), "old Nat reference " + fixture.name);
    return {name: fixture.name, rows: fixture.rows.length};
  });
  result.previous_nat_rows = oldFixtures.reduce((total, fixture) => total + fixture.rows.length, 0);
  result.passed = true;
  return result;
}

module.exports = {run};
if (require.main === module) console.log(JSON.stringify(run(), null, 2));
