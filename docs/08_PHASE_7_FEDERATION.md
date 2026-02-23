# Phase 7: Real Federation Setup

**Goal:** Deploy a real Fedimint federation with independent guardians and oracle arbitrators.
**Prerequisite:** Phase 6 complete (all tests pass on devimint)
**Estimated effort:** 2–4 weeks (mostly social/operational, not coding)

---

## Guardian Setup

A production federation needs minimum 4 guardians (3-of-4 threshold). Guardians should be:
- In different physical locations
- In different legal jurisdictions
- Running different internet providers
- Ideally unknown to each other personally

### Phase 7a: Solo federation (you control all 4)
- 4 VPS instances from different providers (Hetzner, Contabo, Vultr, DigitalOcean)
- Different countries: Germany, Finland, Switzerland, Iceland (all outside Five Eyes)
- You hold all 4 keys — still not fully decentralised but technically a federation
- Use this for public beta testing

### Phase 7b: Community federation
- Recruit 3 independent guardians from Fedimint/Nostr/Bitcoin communities
- Each guardian runs their own node, holds their own key
- You become one guardian of four, or step back entirely
- This is the target end state

---

## Oracle Arbitrator Setup

3 independent arbitrators. Each needs:
- A Nostr keypair (nsec)
- The oracle signing tool (from Phase 3)
- Clear instructions for reviewing evidence and signing outcomes

### Phase 7a: You are all 3 arbitrators (3 keypairs)
- Fine for testing
- Be transparent about this in documentation

### Phase 7b: Real arbitrators
- Recruit from Bitcoin/Nostr communities
- Compensation: fee share from resolved disputes
- Clear written guidelines for what constitutes valid evidence
- No identity required — just a Nostr key and willingness to review

---

## Deployment Tasks

- [ ] 4 VPS instances provisioned
- [ ] Fedimint guardian software deployed on each
- [ ] Federation setup ceremony completed (DKG — distributed key generation)
- [ ] Escrow module deployed to federation
- [ ] Service backend updated to point to real federation
- [ ] Oracle pubkeys configured in module
- [ ] Nostr relay list configured in oracle listener
- [ ] Monitoring set up for guardian health

---

## Grant Applications

Apply once Phase 7a is running:
- **OpenSats**: https://opensats.org/apply
- **HRF**: https://hrf.org/programs/bitcoin-development-fund/
- **Spiral**: https://spiral.xyz/#grants

Write the application around: "non-custodial P2P escrow with Fedimint custody and Nostr oracle dispute resolution — operator cannot be compelled to freeze funds."

---

*This completes the Fedimint Escrow project phases.*
