# Phase 6: Testing

**Goal:** Full end-to-end test coverage on devimint. All edge cases handled.
**Prerequisite:** Phase 5 complete (integration working)
**Estimated effort:** 1 week

---

## Test Scenarios

### Happy path
- [ ] Buyer funds via Lightning → escrow created on devimint
- [ ] Seller marks shipped → buyer releases → seller gets LN payout
- [ ] Buyer requests refund (cooperative) → buyer gets LN refund

### Dispute path
- [ ] Both parties dispute → oracle listener starts
- [ ] 1 oracle signature arrives → nothing happens yet
- [ ] 2nd oracle signature arrives → resolution triggers
- [ ] Winner gets LN payout

### Timeout path
- [ ] Timeout block expires with no resolution
- [ ] Beneficiary claims via timeout input
- [ ] Beneficiary gets LN payout

### Security/edge cases
- [ ] Double-spend attempt (same escrow input twice) → rejected
- [ ] Wrong signature on cooperative release → rejected
- [ ] Oracle signature from unknown pubkey → rejected
- [ ] Two oracle signatures with conflicting outcomes → rejected
- [ ] Timeout claim before block height → rejected
- [ ] Zero amount escrow → rejected
- [ ] Duplicate escrow_id → rejected

### Audit
- [ ] After every operation: sum of federation liabilities = 0
- [ ] No ecash created from thin air
- [ ] No ecash destroyed without corresponding input

---

## Definition of Done

- [ ] All scenarios above pass
- [ ] `cargo test` passes with zero failures
- [ ] devimint E2E test runs without manual intervention
- [ ] Audit reconciliation passes after every test

---

*Next: See 08_PHASE_7_FEDERATION.md*
