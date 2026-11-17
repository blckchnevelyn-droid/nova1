# Current Main CI Verification

This marker exists solely to establish a fresh authoritative GitHub Actions execution on the exact current `main` revision.

The workflow must verify `GITHUB_SHA` against the checked-out revision and execute the complete governed-execution, adversarial, regression, and compileall suite.

No runtime behavior or security contract is changed by this marker.
