# Changing hik-f2b

For people and coding agents who change this repository. The checks enforce
what they can. This file holds what they cannot, and how to run them.

## Checks

Run them from the repository root before you push:

```bash
bash .github/scripts/repo-guard.sh
bash .github/scripts/repo-guard.sh --self-test
bash .github/scripts/docs-check.sh
bash .github/scripts/release-check.sh vX.Y.Z ghcr.io/vladkarok/hik-f2b
```

- `repo-guard.sh` looks for addresses outside `.github/repo-guard-allow.txt`,
  letters that only Russian uses, and binary files. Its header lists the
  modes.
- `docs-check.sh` checks that the READMEs are in step, that links resolve,
  the terms from `GLOSSARY.md`, the length of sentences in steps and
  `hik-f2b.example.ini`. Its exception lists are in `docs-check.py`.
- To run the guard on every commit and push, enable the hooks once:
  `git config core.hooksPath .githooks`. If the push changes Rust code and
  cargo is installed, the pre-push hook also runs `cargo fmt --check`.
- `release-verify.sh` checks a published release in the registry; the
  release workflow runs it, and its header shows how to run it by hand.
- To add your own private strings, name a file outside the repository:
  `git config hikf2b.denylist /path/to/denylist`. The guard header gives the
  format. Never commit that file.
- CI runs all of this, plus `cargo fmt --check`, `cargo clippy` and
  `cargo test`, on every push and pull request. Run those three locally
  too: a Rust toolchain is all they need. `tests/sim.rs` takes more seeds
  from `HIK_F2B_SIM_SEEDS` (its module comment has the rest).

## Rules

- Never commit data from a real network: addresses, ports, host names,
  serial numbers, secrets or chat ids. Use documentation addresses and
  invented names. A published commit cannot be taken back.
- Write a fact about a real device only with evidence. Keep "Tested
  hardware" and "Not yet tried" honest: never write that something was tried
  unless it was.
- The documentation exists in English and Ukrainian. Change both in the same
  commit. Use the terms and the writing rules from `GLOSSARY.md`.
- Add no new dependency and no `unsafe` code without a stated reason.
- The state file format is versioned. Change the version when the format
  changes.
- A change to how a ban is decided or applied needs a test that reproduces
  the scenario.
- Releases are made by tags, as [RELEASING.md](RELEASING.md) says. Try a
  release candidate on real hardware first.
- There is no automatic deployment, by design: hik-f2b changes a firewall,
  so an update is a step that a person takes and watches.
