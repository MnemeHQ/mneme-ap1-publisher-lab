# synthetic/

This lab is synthetic only. Nothing here is real, product, customer or
strategy content, and nothing under this directory is evaluated by the lab
gate except as a test target.

The lab's decision memory is `.mneme/project_memory.json` (synthetic ADR-901,
the same fixture the ADR-033 C4 Gate 3 lab used). It carries one literal
constraint, `FORBID_LITERAL`, scoped to `docs/**` (excluding `docs/history/**`).
A test pull request that adds a file under `docs/` containing the forbidden
literal named in that memory produces a violation report from the trusted gate;
a pull request that does not contain it produces a PASS report.

The forbidden literal is deliberately not written in any file on `main`. Test
pull requests introduce it on their own branch only, inside the gate's scoped
path.
