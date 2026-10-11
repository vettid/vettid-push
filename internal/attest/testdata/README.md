`aws-attestation-2025-09-16.b64` is a real AWS Nitro Enclaves attestation
document (base64), copied from vettid-vault `vms/nitro/testdata` (there
from the test fixtures of tkhq/rust-sdk, `proofs/src/lib.rs`, Apache-2.0,
https://github.com/tkhq/rust-sdk). It is public data: PCRs, an ephemeral
public key, user_data and the AWS certificate chain of an enclave that ran
on 2025-09-16. The tests use it to show that the pinned AWS root anchors a
real document.
