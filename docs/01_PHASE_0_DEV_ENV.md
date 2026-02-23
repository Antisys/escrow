# Phase 0: Development Environment

**Goal:** Fedimint compiles locally, devimint test federation runs successfully.
**Prerequisite:** None — this is the starting point.
**Estimated effort:** 1–3 days

---

## Context for Claude

This phase has nothing to do with writing escrow logic. It is purely about getting the Fedimint development toolchain working on the developer's machine so that subsequent phases can compile and test Rust code.

The developer's machine:
- OS: Ubuntu Linux, x86_64
- RAM: 15 GB
- Disk: ~187 GB free on root, ~976 MB free on /home (tight)
- Nix: installed at `/nix/var/nix/profiles/default/bin/nix`
- Fedimint repo: cloned at `/home/ralf/fedimint`

**Important:** The /home partition is nearly full. The Nix store goes to /nix (root partition, fine). But build artifacts and the repo itself are on /home. Monitor disk usage carefully.

---

## Tasks

### Task 0.1 — Verify Nix installation

```bash
export PATH="/nix/var/nix/profiles/default/bin:$PATH"
nix --version
```

Expected: `nix (Nix) 2.33.x`

If it fails: Nix daemon may not be running. Check with:
```bash
systemctl status nix-daemon
```

---

### Task 0.2 — Enter Fedimint dev shell

```bash
cd /home/ralf/fedimint
export PATH="/nix/var/nix/profiles/default/bin:$PATH"
nix develop
```

This downloads the full Rust toolchain and all dependencies via the Nix flake. **First run takes 20–40 minutes.** Subsequent runs are instant (cached).

When complete, you will see a shell prompt indicating you are inside the dev environment. The prompt may change or show `(nix develop)`.

Verify inside the shell:
```bash
rustc --version    # should show Rust 1.7x.x
cargo --version    # should show Cargo 1.7x.x
devimint --help    # should show devimint commands
```

---

### Task 0.3 — Run devimint smoke test

Inside the nix develop shell:

```bash
cd /home/ralf/fedimint
cargo build 2>&1 | tail -20
```

This compiles the full Fedimint codebase. **Takes 15–45 minutes on first run.** Subsequent runs are incremental (fast).

Expected: ends with something like:
```
Finished `dev` profile [unoptimized + debuginfo] target(s) in Xm Xs
```

If it fails with disk full errors: the /home partition ran out of space. Move cargo target directory to root partition:
```bash
export CARGO_TARGET_DIR=/tmp/fedimint-target
cargo build
```

---

### Task 0.4 — Run a minimal devimint federation

Inside the nix develop shell:

```bash
cd /home/ralf/fedimint
cargo build --bin devimint
./scripts/tests/reconnect-test.sh
```

Or use the simpler:
```bash
devimint dev-fed
```

This starts a local test federation with 4 guardians. Verify it starts without errors.

---

### Task 0.5 — Read the custom modules example

```bash
cd /home/ralf
git clone https://github.com/fedimint/fedimint-custom-modules-example
cat fedimint-custom-modules-example/README.md
```

Read through the example module to understand:
- File structure (common / server / client)
- How the dummy module works (locks ecash to a pubkey, unlocks with signature)
- What needs to be modified to create a new module

---

## Definition of Done

- [ ] `nix --version` returns successfully
- [ ] `nix develop` completes without error
- [ ] `rustc --version` works inside nix develop shell
- [ ] `devimint --help` works inside nix develop shell
- [ ] `cargo build` compiles full Fedimint without errors
- [ ] Custom modules example is cloned and README is read

---

## Common Problems

**"nix: command not found"**
Add to PATH: `export PATH="/nix/var/nix/profiles/default/bin:$PATH"`

**"disk full" during cargo build**
Set: `export CARGO_TARGET_DIR=/tmp/fedimint-target`

**"untrusted substituter" warning during nix develop**
Add to `/etc/nix/nix.conf`:
```
trusted-users = root ralf
```
Then restart: `sudo systemctl restart nix-daemon`

**nix develop hangs**
Normal — it is downloading gigabytes of dependencies. Check progress with `df -h /nix`.

---

*Next: See 02_PHASE_1_SKELETON.md*
