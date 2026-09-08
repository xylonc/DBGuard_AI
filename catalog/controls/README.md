# Control catalogue status: foundation

`hardening-controls.yaml` is now loaded through a strict, fail-closed assessment
catalogue loader. It contains the approved template-assessment definitions and
the contracts for knowledge sources, assessment providers, baseline profiles,
and baseline controls.

The CIS/industry baseline is still `NOT_READY`: its profile and control lists
remain empty until the converted benchmark is reviewed and assigned exact rule
IDs, applicability, evidence requirements, and assessment providers. The twin
executor and CIS-CAT runner are not implemented yet.

`examples/` preserves an older design example and is not loaded at runtime.
