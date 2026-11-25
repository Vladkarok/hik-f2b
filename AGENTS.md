# Changing hik-f2b

For people and coding agents who change this repository. The checks enforce
what they can. This file holds what they cannot, and how to run them.

## Checks

Run them all with one command before you push:

```bash
bash .github/scripts/check-all.sh
```

It works from any directory of the repository. It stops at the first
failed step; `--keep-going` runs every step and reports all that failed.
It finds cargo in `~/.cargo/bin` if cargo is not on PATH, and says what is
missing. The steps, cheapest first, can also be run one by one:

```bash
bash .github/scripts/repo-guard.sh
bash .github/scripts/repo-guard.sh --self-test
bash .github/scripts/docs-check.sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

Before a release, also run
`bash .github/scripts/release-check.sh vX.Y.Z ghcr.io/vladkarok/hik-f2b`.

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
- CI runs all of this on every push and pull request, plus the guard on
  every pushed commit, the tests on arm64, `cargo audit` and the image
  checks. `tests/sim.rs` takes more seeds from `HIK_F2B_SIM_SEEDS` (its
  module comment has the rest).
- `.github/workflows/sim.yml` runs `tests/sim.rs` with 4000 seeds per class
  every Sunday, on seeds no earlier run covered, through
  `.github/scripts/sim-long.sh` (its header has the rules). Start a run by
  hand with `gh workflow run sim.yml -f seeds=200`. A violation fails the
  run; the job summary names the seed and the replay command.

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
- Nothing read from an NVR log may reach the set of own addresses
  (`src/own.rs`, ADR 0004). hik-f2b removes an address-list entry only for
  an own address (ADR 0005).
- Only own addresses go into the safe list, and hik-f2b adds or changes no
  firewall rule (ADR 0006).
- Releases are made by tags, as [RELEASING.md](RELEASING.md) says. Try a
  release candidate on real hardware first.
- There is no automatic deployment, by design: hik-f2b changes a firewall,
  so an update is a step that a person takes and watches.

## Agent skills

### Issue tracker

Issues and specs are Markdown files under `.scratch/`, which Git ignores.
See `docs/agents/issue-tracker.md`.

### Triage labels

The five default triage roles, written as `Status:` in each issue file. See
`docs/agents/triage-labels.md`.

### Domain docs

Single-context: `GLOSSARY.md` and `docs/adr/` at the repository root. See
`docs/agents/domain.md`.
