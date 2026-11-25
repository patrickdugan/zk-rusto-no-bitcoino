/-
ZKL-NOVA-18: export actual compiled Lean declarations without lowering Expr.

  lean --run corpus_export.lean --search-path /path/to/olean/root \
    --module Actual.Module --out targets.jsonl --dependency-out dependencies.jsonl

Module ownership comes from Lean's environment, rather than a name prefix.
The summary records import failures; source compilation receipts belong to the
caller. Standard-library runs are implementation tests, not corpus coverage.
-/
import Lean

set_option autoImplicit false
set_option maxRecDepth 8192

open Lean
namespace CorpusExport

def obj (xs : List (String × Json)) : Json := Json.mkObj xs
def str (s : String) : Json := Json.str s
def num (n : Nat) : Json := toJson n
def strings (xs : Array String) : Json := toJson xs
def names (xs : Array Name) : Json := strings (xs.map Name.toString)

def nameParts : Name → List Json
  | .anonymous => []
  | .str p s => nameParts p ++ [obj [("kind", str "string"), ("value", str s)]]
  | .num p n => nameParts p ++ [obj [("kind", str "number"), ("value", str (toString n))]]

def named (key : String) (n : Name) : List (String × Json) :=
  [(key, str n.toString), (key ++ "_parts", toJson (nameParts n))]

structure Config where
  modules : Array Name := #[]
  selectedNames : Array String := #[]
  searchPaths : List System.FilePath := []
  output : System.FilePath := "corpus.jsonl"
  dependencyOutput : Option System.FilePath := none
  summaryOutput : Option System.FilePath := none
  maxNodes : Nat := 200000
  maxDepth : Nat := 2048
  maxBytes : Nat := 67108864
  maxAxiomDecls : Nat := 20000
  maxDependencies : Nat := 20000
  maxHeartbeats : Nat := 2000000
  recheck : Bool := true
  allDeclarations : Bool := false
  deriving Inhabited

def Config.summaryPath (c : Config) : System.FilePath :=
  c.summaryOutput.getD (System.FilePath.mk (c.output.toString ++ ".summary.json"))

partial def parseArgs (c : Config) : List String → Except String Config
  | [] => if c.modules.isEmpty then .error "at least one --module is required" else .ok c
  | "--module" :: x :: xs => parseArgs { c with modules := c.modules.push x.toName } xs
  | "--name" :: x :: xs => parseArgs { c with selectedNames := c.selectedNames.push x } xs
  | "--search-path" :: x :: xs => parseArgs { c with searchPaths := c.searchPaths ++ [System.FilePath.mk x] } xs
  | "--out" :: x :: xs => parseArgs { c with output := x } xs
  | "--dependency-out" :: x :: xs => parseArgs { c with dependencyOutput := some x } xs
  | "--summary-out" :: x :: xs => parseArgs { c with summaryOutput := some x } xs
  | "--no-recheck" :: xs => parseArgs { c with recheck := false } xs
  | "--all-declarations" :: xs => parseArgs { c with allDeclarations := true } xs
  | flag :: value :: xs => do
    let n ← match value.toNat? with
      | some n => pure n
      | none => throw s!"{flag} requires a natural number"
    if n == 0 then throw s!"{flag} must be positive"
    let c ← match flag with
      | "--max-nodes" => pure { c with maxNodes := n }
      | "--max-depth" => pure { c with maxDepth := n }
      | "--max-bytes" => pure { c with maxBytes := n }
      | "--max-axiom-declarations" => pure { c with maxAxiomDecls := n }
      | "--max-dependencies" => pure { c with maxDependencies := n }
      | "--max-heartbeats" => pure { c with maxHeartbeats := n }
      | _ => throw s!"unknown option {flag}"
    parseArgs c xs
  | x :: [] => .error s!"missing argument or unknown option {x}"

structure Dag where
  exprNodes : Array Json := #[]
  levelNodes : Array Json := #[]
  exprIds : ExprStructMap Nat := {}
  levelIds : Std.HashMap Level Nat := {}
  references : Array (Name × Array Nat) := #[]
  visits : Nat := 0
  maxDepthSeen : Nat := 0
  nodeBytes : Nat := 0
  deriving Inhabited

abbrev EncodeM := ReaderT Config (ExceptT String (StateM Dag))

def tick (depth : Nat) : EncodeM Unit := do
  let c ← read
  let s ← get
  if depth > c.maxDepth then throw "resource_limit: expression or level depth"
  if s.visits >= 4 * c.maxNodes then throw "resource_limit: traversal visits"
  modify fun s => { s with visits := s.visits + 1, maxDepthSeen := max s.maxDepthSeen depth }

def checkNodeBudget (node : Json) : EncodeM Unit := do
  let c ← read
  let s ← get
  if s.exprNodes.size + s.levelNodes.size >= c.maxNodes then
    throw "resource_limit: DAG nodes"
  let bytes := node.compress.utf8ByteSize
  if s.nodeBytes + bytes > c.maxBytes then throw "resource_limit: DAG node bytes"
  modify fun s => { s with nodeBytes := s.nodeBytes + bytes }

def checkedString (s : String) : EncodeM Json := do
  if s.utf8ByteSize > (← read).maxBytes then throw "resource_limit: string bytes"
  return str s

partial def encodeLevel (l : Level) (depth : Nat := 0) : EncodeM Nat := do
  tick depth
  if let some id := (← get).levelIds[l]? then return id
  let node ← match l with
    | .zero => pure <| obj [("tag", str "zero")]
    | .succ a => do
      let a ← encodeLevel a (depth + 1)
      pure <| obj [("tag", str "succ"), ("of", num a)]
    | .max a b => do
      let a ← encodeLevel a (depth + 1)
      let b ← encodeLevel b (depth + 1)
      pure <| obj [("tag", str "max"), ("left", num a), ("right", num b)]
    | .imax a b => do
      let a ← encodeLevel a (depth + 1)
      let b ← encodeLevel b (depth + 1)
      pure <| obj [("tag", str "imax"), ("left", num a), ("right", num b)]
    | .param n => pure <| obj (("tag", str "param") :: named "name" n)
    | .mvar n => pure <| obj (("tag", str "mvar") :: named "name" n.name)
  checkNodeBudget node
  let id := (← get).levelNodes.size
  modify fun s => { s with levelNodes := s.levelNodes.push node, levelIds := s.levelIds.insert l id }
  return id

def binderName : BinderInfo → String
  | .default => "default"
  | .implicit => "implicit"
  | .strictImplicit => "strictImplicit"
  | .instImplicit => "instImplicit"

def encodeMetadata (md : MData) : EncodeM Json := do
  let entries ← md.entries.toArray.mapM fun (key, value) => do
    let fields ← match value with
      | .ofString x => pure [("kind", str "string"), ("value", ← checkedString x)]
      | .ofBool x => pure [("kind", str "bool"), ("value", toJson x)]
      | .ofName x => pure (("kind", str "name") :: named "value" x)
      | .ofNat x => pure [("kind", str "nat"), ("value", ← checkedString (toString x))]
      | .ofInt x => pure [("kind", str "int"), ("value", ← checkedString (toString x))]
      | .ofSyntax x => pure [("kind", str "syntax"), ("encoding", str "Lean.Syntax.repr"),
          ("value", ← checkedString (reprStr x))]
    pure <| obj (named "key" key ++ fields)
  return toJson entries

partial def encodeExpr (e : Expr) (depth : Nat := 0) : EncodeM Nat := do
  tick depth
  -- Expr's default equality ignores binder names/annotations. ExprStructMap
  -- uses exact structural equality and retains these fields during sharing.
  let key : ExprStructEq := { val := e }
  if let some id := (← get).exprIds[key]? then return id
  let node ← match e with
    | .bvar i => pure <| obj [("tag", str "bvar"), ("index", num i)]
    | .fvar n => pure <| obj (("tag", str "fvar") :: named "name" n.name)
    | .mvar n => pure <| obj (("tag", str "mvar") :: named "name" n.name)
    | .sort l => do
      let l ← encodeLevel l (depth + 1)
      pure <| obj [("tag", str "sort"), ("level", num l)]
    | .const n ls => do
      let ls ← ls.toArray.mapM (fun l => encodeLevel l (depth + 1))
      modify fun s => { s with references := s.references.push (n, ls) }
      pure <| obj (("tag", str "const") :: (named "name" n ++ [("levels", toJson ls)]))
    | .app f a => do
      let f ← encodeExpr f (depth + 1)
      let a ← encodeExpr a (depth + 1)
      pure <| obj [("tag", str "app"), ("fn", num f), ("arg", num a)]
    | .lam n t b bi => do
      let t ← encodeExpr t (depth + 1)
      let b ← encodeExpr b (depth + 1)
      pure <| obj (("tag", str "lam") :: (named "name" n ++
        [("binder_info", str (binderName bi)), ("type", num t), ("body", num b)]))
    | .forallE n t b bi => do
      let t ← encodeExpr t (depth + 1)
      let b ← encodeExpr b (depth + 1)
      pure <| obj (("tag", str "forall") :: (named "name" n ++
        [("binder_info", str (binderName bi)), ("type", num t), ("body", num b)]))
    | .letE n t v b nd => do
      let t ← encodeExpr t (depth + 1)
      let v ← encodeExpr v (depth + 1)
      let b ← encodeExpr b (depth + 1)
      pure <| obj (("tag", str "let") :: (named "name" n ++
        [("type", num t), ("value", num v), ("body", num b), ("non_dep", toJson nd)]))
    | .lit (.natVal n) => pure <| obj [("tag", str "lit"), ("literal_kind", str "nat"),
        ("value", ← checkedString (toString n))]
    | .lit (.strVal s) => pure <| obj [("tag", str "lit"), ("literal_kind", str "string"),
        ("value", ← checkedString s)]
    | .mdata md b => do
      let b ← encodeExpr b (depth + 1)
      let md ← encodeMetadata md
      pure <| obj [("tag", str "mdata"), ("expr", num b), ("metadata", md)]
    | .proj n i b => do
      let b ← encodeExpr b (depth + 1)
      pure <| obj (("tag", str "proj") :: (named "type_name" n ++ [("index", num i), ("expr", num b)]))
  checkNodeBudget node
  let id := (← get).exprNodes.size
  modify fun s => { s with
    exprNodes := s.exprNodes.push node
    exprIds := s.exprIds.insert key id }
  return id

def kind : ConstantInfo → String
  | .axiomInfo _ => "axiom"
  | .defnInfo _ => "definition"
  | .thmInfo _ => "theorem"
  | .opaqueInfo _ => "opaque"
  | .quotInfo _ => "quotient"
  | .inductInfo _ => "inductive"
  | .ctorInfo _ => "constructor"
  | .recInfo _ => "recursor"

def safety (ci : ConstantInfo) : String :=
  if ci.isUnsafe then "unsafe" else if ci.isPartial then "partial" else "safe"

def moduleFor (env : Environment) (n : Name) : Option Name := do
  let i ← env.getModuleIdxFor? n
  (env.header.moduleNames[i]?)

def moduleJson (env : Environment) (n : Name) : Json :=
  (moduleFor env n).map (str ∘ Name.toString) |>.getD Json.null

def exceptionKind : Kernel.Exception → String
  | .unknownConstant _ n => s!"unknown_constant: {n}"
  | .alreadyDeclared _ n => s!"already_declared: {n}"
  | .declTypeMismatch .. => "declaration_type_mismatch"
  | .declHasMVars .. => "declaration_has_metavariables"
  | .declHasFVars .. => "declaration_has_free_variables"
  | .funExpected .. => "function_expected"
  | .typeExpected .. => "type_expected"
  | .letTypeMismatch .. => "let_type_mismatch"
  | .exprTypeMismatch .. => "expression_type_mismatch"
  | .appTypeMismatch .. => "application_type_mismatch"
  | .invalidProj .. => "invalid_projection"
  | .thmTypeIsNotProp .. => "theorem_type_is_not_prop"
  | .other s => s
  | .deterministicTimeout => "resource_limit: kernel_heartbeats"
  | .excessiveMemory => "resource_limit: kernel_memory"
  | .deepRecursion => "resource_limit: kernel_recursion"
  | .interrupted => "interrupted"

def proofClassification (env : Environment) (ci : ConstantInfo) : Json × Json :=
  match Kernel.check env {} ci.type with
  | .error e => (Json.null, str (exceptionKind e))
  | .ok type => match Kernel.whnf env {} type with
    | .ok (.sort l) => (toJson (l == Level.zero), Json.null)
    | .ok _ => (Json.null, str "declared_type_did_not_infer_a_sort")
    | .error e => (Json.null, str (exceptionKind e))

-- Lean 4.35 adds an explicit kernel recursion bound to this checked API.
-- Elaboration selects the applicable signature; both branches typecheck the
-- copied declaration through the kernel and preserve the heartbeat bound.
def kernelAddChecked (env : Kernel.Environment) (heartbeats _recursion : USize)
    (decl : Declaration) : Except Kernel.Exception Kernel.Environment := by
  first
  | exact Kernel.Environment.addDeclCore env heartbeats _recursion decl none
  | exact Kernel.Environment.addDeclCore env heartbeats decl none

def recheck (env : Environment) (c : Config) (ci : ConstantInfo) : Json := Id.run do
  if !c.recheck then return obj [("status", str "not_requested")]
  let fresh := Name.str (Name.str .anonymous "_zkl_export_kernel_check") ci.name.toString
  if env.contains fresh then return obj [("status", str "error"), ("error", str "check_name_collision")]
  let decl? := match ci with
    | .thmInfo v => some <| Declaration.thmDecl { v with name := fresh, all := [] }
    | .defnInfo v => some <| Declaration.defnDecl { v with name := fresh, all := [] }
    | .opaqueInfo v => some <| Declaration.opaqueDecl { v with name := fresh, all := [] }
    | _ => none
  let some decl := decl? | return obj [("status", str "signature_only")]
  match kernelAddChecked env.checked.get c.maxHeartbeats.toUSize c.maxDepth.toUSize decl with
  | .ok _ => return obj [("status", str "passed"), ("max_heartbeats", num c.maxHeartbeats)]
  | .error e => return obj [("status", str "error"), ("error", str (exceptionKind e))]

-- This follows Lean.collectAxioms: declaration types and values are traversed,
-- including constructor types of inductives. The explicit declaration bound
-- yields an incomplete status rather than claiming an empty axiom dependency.
def axiomDependencies (env : Environment) (root : Name) (limit : Nat) : Json := Id.run do
  let mut queue := #[root]
  let mut offset := 0
  let mut visited : NameSet := {}
  let mut scheduled : NameSet := ({} : NameSet).insert root
  let mut axioms : Array Name := #[]
  let mut missing : Array Name := #[]
  let mut boundedEdges := 0
  while offset < queue.size && visited.size < limit do
    let n := queue[offset]!
    offset := offset + 1
    if visited.contains n then continue
    visited := visited.insert n
    match env.checked.get.find? n with
    | none => missing := missing.push n
    | some ci =>
      if ci.isAxiom then axioms := axioms.push n
      let mut refs := ci.type.getUsedConstants
      if let some v := ci.value? (allowOpaque := true) then
        refs := refs ++ v.getUsedConstants
      if let .inductInfo v := ci then
        refs := refs ++ v.ctors.toArray
      for r in refs do
        if !scheduled.contains r then
          if queue.size < limit then
            scheduled := scheduled.insert r
            queue := queue.push r
          else boundedEdges := boundedEdges + 1
  let complete := offset == queue.size && missing.isEmpty && boundedEdges == 0
  return obj [("status", str (if complete then "complete" else "incomplete")),
    ("axioms", names (axioms.qsort (fun a b => a.toString < b.toString))),
    ("missing_constants", names missing), ("visited_declarations", num visited.size),
    ("pending_queue_entries", num (queue.size - offset)), ("limit", num limit),
    ("resource_limited_edges", num boundedEdges),
    ("contains_sorry_ax", toJson (axioms.contains ``sorryAx))]

def referenceInfo (env : Environment) (r : Name × Array Nat) : Json :=
  let ci := env.find? r.1
  obj (named "name" r.1 ++ [("levels", toJson r.2),
    ("kind", ci.map (str ∘ kind) |>.getD (str "missing")),
    ("module", moduleJson env r.1),
    ("safety", ci.map (str ∘ safety) |>.getD Json.null),
    ("level_params", ci.map (fun x => names x.levelParams.toArray) |>.getD Json.null),
    ("unsafe", ci.map (toJson ∘ ConstantInfo.isUnsafe) |>.getD Json.null),
    ("partial", ci.map (toJson ∘ ConstantInfo.isPartial) |>.getD Json.null)])

def encodeDeclaration (env : Environment) (c : Config) (role : String) (ci : ConstantInfo) : Json × Array Name := Id.run do
  let includeValue := role == "target" || kind ci == "definition"
  let encode : EncodeM (Nat × Option Nat) := do
    let t ← encodeExpr ci.type
    let v ← match if includeValue then ci.value? (allowOpaque := true) else none with
      | some v => do pure <| some (← encodeExpr v)
      | none => pure none
    return (t, v)
  let (result, dag) := ((encode.run c).run).run {}
  let (isProof, classificationError) := proofClassification env ci
  let (status, typeRoot, proofRoot, diagnostics) := match result with
    | .ok (t, v) => ("ok", num t, v.map num |>.getD Json.null, #[])
    | .error error =>
      (if "resource_limit:".isPrefixOf error then "resource_limit" else "error",
        Json.null, Json.null, #[error])
  let record := obj ([("schema", str "zkl-nova-18/lean-expr-v1"), ("role", str role)] ++
    named "name" ci.name ++ [
    ("kind", str (kind ci)), ("safety", str (safety ci)), ("level_params", names ci.levelParams.toArray),
    ("value_status", str (if status != "ok" then "extraction_incomplete"
      else if !ci.hasValue (allowOpaque := true) then "no_value"
      else if includeValue then "exported" else "not_requested_dependency_signature")),
    ("level_param_parts", toJson (ci.levelParams.map (fun x => toJson (nameParts x)))),
    ("is_proof", isProof), ("classification_error", classificationError),
    ("status", str status), ("diagnostics", toJson diagnostics),
    ("type_root", typeRoot), ("proof_root", proofRoot),
    ("expr_nodes", toJson dag.exprNodes), ("level_nodes", toJson dag.levelNodes),
    ("constants", toJson (dag.references.map (referenceInfo env))),
    ("counts", obj [("expr_nodes", num dag.exprNodes.size), ("level_nodes", num dag.levelNodes.size),
      ("traversal_visits", num dag.visits), ("max_depth", num dag.maxDepthSeen),
      ("dag_node_bytes", num dag.nodeBytes)]),
    ("provenance", obj [("module", moduleJson env ci.name), ("lean_version", str Lean.versionString),
      ("unsafe", toJson ci.isUnsafe), ("partial", toJson ci.isPartial),
      ("kernel_check", if role == "dependency" then obj [("status", str "imported_compiled_declaration")]
        else if status == "ok" then recheck env c ci else obj [("status", str "not_attempted")]),
      ("axiom_dependencies", if role == "target" then axiomDependencies env ci.name c.maxAxiomDecls
        else obj [("status", str "covered_by_target_audit")]),
      ("source_compilation_evidence", str (if role == "dependency" then "imported_compiled_declaration"
        else "external_module_build_receipt_required")),
      ("eta_or_proof_irrelevance_usage", str "not_inferred_from_expr")])])
  return (record, dag.references.map Prod.fst)

def resourceRecord (env : Environment) (role : String) (ci : ConstantInfo) (reason : String) : Json :=
  obj [("schema", str "zkl-nova-18/lean-expr-v1"), ("role", str role), ("name", str ci.name.toString),
    ("kind", str (kind ci)), ("level_params", names ci.levelParams.toArray), ("is_proof", Json.null),
    ("classification_error", str reason), ("status", str "resource_limit"),
    ("type_root", Json.null), ("proof_root", Json.null), ("expr_nodes", toJson (#[] : Array Json)),
    ("level_nodes", toJson (#[] : Array Json)), ("constants", toJson (#[] : Array Json)),
    ("diagnostics", strings #[reason]), ("provenance", obj [("module", moduleJson env ci.name)])]

def writeDeclaration (handle : IO.FS.Handle) (env : Environment) (c : Config)
    (role : String) (ci : ConstantInfo) : IO (Array Name × String) := do
  let (record, references) := encodeDeclaration env c role ci
  let text := record.compress
  if text.utf8ByteSize > c.maxBytes then
    handle.putStrLn (resourceRecord env role ci "resource_limit: JSON record bytes").compress
    return (references, "resource_limit")
  handle.putStrLn text
  return (references, (record.getObjValAs? String "status").toOption.getD "error")

structure Progress where
  phase : String := "locate_modules"
  moduleFiles : Array Json := #[]
  loadedModules : Array Name := #[]
  targetRecords : Nat := 0

def run (c : Config) (progress : IO.Ref Progress) : IO UInt32 := do
  -- --run may use an absolute Lean binary absent from PATH.
  initSearchPath (← findSysroot (← IO.appPath).toString) c.searchPaths
  let mut moduleFiles : Array Json := #[]
  for m in c.modules do
    let p ← findOLean m
    moduleFiles := moduleFiles.push <| obj [("module", str m.toString), ("olean_path", str p.toString)]
    progress.modify fun s => { s with moduleFiles := moduleFiles }
  progress.modify fun s => { s with phase := "import_modules" }
  let env ← importModules (c.modules.map fun m => { module := m }) {} (trustLevel := 0)
  progress.modify fun s => { s with phase := "export_targets", loadedModules := c.modules }
  let mut targets : Array ConstantInfo := #[]
  for (n, ci) in env.constants do
    let owned := (moduleFor env n).any (fun m => c.modules.contains m)
    let selected := c.selectedNames.isEmpty || c.selectedNames.contains n.toString
    if owned && selected && (c.allDeclarations || ci.hasValue (allowOpaque := true)) then
      targets := targets.push ci
  targets := targets.qsort (fun a b => a.name.toString < b.name.toString)
  let missingNames := c.selectedNames.filter fun n => !targets.any (fun ci => ci.name.toString == n)
  let (dependencies, targetStatus) ← IO.FS.withFile c.output .write fun h => do
    let mut dependencies := #[``Nat, ``Nat.zero, ``Nat.succ, ``Nat.rec, ``Eq, ``Eq.refl, ``Eq.rec]
    let mut targetStatus : Array String := #[]
    for ci in targets do
      let (refs, status) ← writeDeclaration h env c "target" ci
      dependencies := dependencies ++ refs
      targetStatus := targetStatus.push status
      progress.modify fun s => { s with targetRecords := s.targetRecords + 1 }
    pure (dependencies, targetStatus)
  progress.modify fun s => { s with phase := "export_dependencies" }
  let (dependencyCount, dependencyPending, dependencyBounded) ← match c.dependencyOutput with
    | none => pure (0, 0, 0)
    | some file => IO.FS.withFile file .write fun h => do
      let mut queue : Array Name := #[]
      let mut scheduled : NameSet := {}
      let mut bounded := 0
      for n in dependencies do
        if !scheduled.contains n then
          if queue.size < c.maxDependencies then
            scheduled := scheduled.insert n
            queue := queue.push n
          else bounded := bounded + 1
      let mut dependencyCount := 0
      let mut offset := 0
      while offset < queue.size do
        let n := queue[offset]!
        offset := offset + 1
        if let some ci := env.find? n then
          let (refs, _) ← writeDeclaration h env c "dependency" ci
          for r in refs do
            if !scheduled.contains r then
              if queue.size < c.maxDependencies then
                scheduled := scheduled.insert r
                queue := queue.push r
              else bounded := bounded + 1
          dependencyCount := dependencyCount + 1
      pure (dependencyCount, queue.size - offset, bounded)
  let summary := obj [("schema", str "zkl-nova-18/lean-expr-summary-v1"),
    ("status", str (if missingNames.isEmpty then "completed" else "selection_error")),
    ("lean_version", str Lean.versionString), ("requested_modules", names c.modules),
    ("requested_module_count", num c.modules.size), ("loaded_module_count", num c.modules.size),
    ("failed_modules", toJson (#[] : Array Json)), ("failed_module_count", num 0),
    ("module_files", toJson moduleFiles), ("target_records", num targets.size),
    ("target_ok", num (targetStatus.filter (· == "ok")).size),
    ("target_resource_limited", num (targetStatus.filter (· == "resource_limit")).size),
    ("target_errors", num (targetStatus.filter (· == "error")).size),
    ("missing_selected_names", strings missingNames), ("dependency_records", num dependencyCount),
    ("dependency_pending_queue_entries", num dependencyPending),
    ("dependency_resource_limited_edges", num dependencyBounded),
    ("dependency_policy", str "definition_values_and_other_declaration_signatures"),
    ("dependency_limit", num c.maxDependencies),
    ("limits", obj [("nodes", num c.maxNodes), ("depth", num c.maxDepth), ("record_bytes", num c.maxBytes),
      ("axiom_declarations", num c.maxAxiomDecls), ("kernel_heartbeats", num c.maxHeartbeats)]),
    ("source_compilation_evidence", str "external_module_build_receipt_required")]
  IO.FS.writeFile c.summaryPath (summary.pretty ++ "\n")
  (← IO.getStderr).putStrLn summary.compress
  return if missingNames.isEmpty then 0 else 2

end CorpusExport

def main (args : List String) : IO UInt32 := do
  match CorpusExport.parseArgs {} args with
  | .error e =>
    (← IO.getStderr).putStrLn e
    return (2 : UInt32)
  | .ok c =>
    let progress ← IO.mkRef ({} : CorpusExport.Progress)
    try CorpusExport.run c progress catch e =>
      let p ← progress.get
      let failed := c.modules.filter (fun m => !p.loadedModules.contains m)
      let failure := CorpusExport.obj [("schema", CorpusExport.str "zkl-nova-18/lean-expr-summary-v1"),
        ("status", CorpusExport.str "export_error"), ("error", CorpusExport.str e.toString),
        ("requested_modules", CorpusExport.names c.modules),
        ("requested_module_count", CorpusExport.num c.modules.size),
        ("loaded_module_count", CorpusExport.num p.loadedModules.size),
        ("failed_module_count", CorpusExport.num failed.size),
        ("failed_modules", toJson (failed.map fun m => CorpusExport.obj
          [("module", CorpusExport.str m.toString), ("error", CorpusExport.str e.toString)])),
        ("module_files", toJson p.moduleFiles), ("phase", CorpusExport.str p.phase),
        ("target_records_written", CorpusExport.num p.targetRecords),
        ("source_compilation_evidence", CorpusExport.str "external_module_build_receipt_required")]
      IO.FS.writeFile c.summaryPath (failure.pretty ++ "\n")
      (← IO.getStderr).putStrLn failure.compress
      return (1 : UInt32)
