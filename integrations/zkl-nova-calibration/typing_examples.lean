def zkl_identity : (∀ (x0 : (Sort 0)), (∀ (x1 : x0), x0)) :=
  (fun (x0 : (Sort 0)) => (fun (x1 : x0) => x1))
#print axioms zkl_identity

def zkl_dependent_app : (∀ (x0 : (Sort 1)), (∀ (x1 : (∀ (x1 : x0), (Sort 1))), (∀ (x2 : (∀ (x2 : x0), (x1 x2))), (∀ (x3 : x0), (x1 x3))))) :=
  (fun (x0 : (Sort 1)) => (fun (x1 : (∀ (x1 : x0), (Sort 1))) => (fun (x2 : (∀ (x2 : x0), (x1 x2))) => (fun (x3 : x0) => (x2 x3)))))
#print axioms zkl_dependent_app

def zkl_weakening : (∀ (x0 : (Sort 0)), (∀ (x1 : (Sort 0)), (∀ (x2 : x0), (∀ (x3 : x1), x0)))) :=
  (fun (x0 : (Sort 0)) => (fun (x1 : (Sort 0)) => (fun (x2 : x0) => (fun (x3 : x1) => x2))))
#print axioms zkl_weakening

def zkl_conversion : (∀ (x0 : (Sort 0)), (∀ (x1 : x0), ((fun (x2 : (Sort 0)) => x2) x0))) :=
  (fun (x0 : (Sort 0)) => (fun (x1 : x0) => x1))
#print axioms zkl_conversion

def zkl_impredicative_pi : (Sort 2) :=
  (∀ (x0 : (Sort 1)), (∀ (x1 : (∀ (x1 : x0), (Sort 0))), (Sort 0)))
#print axioms zkl_impredicative_pi
