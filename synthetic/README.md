# synthetic/

This lab is synthetic only. Nothing here is real, product, customer or
strategy content.

The lab's decision memory is `.mneme/project_memory.json` (synthetic ADR-901,
the same fixture the ADR-033 C4 Gate 3 lab used). It carries one literal
constraint, `FORBID_LITERAL`, scoped to `docs/**` (excluding `docs/history/**`).
The literal itself is written only in that memory file. A test pull request that
adds a file under `docs/` containing it produces a violation report from the
trusted gate; a pull request that does not contain it produces a PASS report.

No file under this directory contains the literal, and test pull requests
introduce it on their own branch only.
