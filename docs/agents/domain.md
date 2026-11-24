# Domain Docs

How the engineering skills should consume this repository's domain
documentation when exploring the codebase.

## Before exploring, read these

- **[GLOSSARY.md](../../GLOSSARY.md)** at the repository root. It gives one
  term for each concept, in English and in Ukrainian, and the words not to
  use for it.
- **`docs/adr/`**: read ADRs that touch the area you're about to work in.

If `docs/adr/` doesn't exist, **proceed silently**. Don't flag its absence;
don't suggest creating it upfront. The `/domain-modeling` skill (reached via
`/grill-with-docs` and `/improve-codebase-architecture`) creates it lazily
when decisions actually get resolved.

## File structure

This is a single-context repository:

```
/
├── GLOSSARY.md
├── docs/adr/
└── src/
```

## Use the glossary's vocabulary

When your output names a domain concept (in an issue title, a refactor
proposal, a hypothesis, a test name), use the term as defined in
`GLOSSARY.md`. Don't drift to synonyms the glossary explicitly avoids: the
"Do not use" column lists them, and `.github/scripts/docs-check.sh` fails
when one appears in the documentation.

If the concept you need isn't in the glossary yet, that's a signal: either
you're inventing language the project doesn't use (reconsider) or there's a
real gap (note it for `/domain-modeling`).

## Flag ADR conflicts

If your output contradicts an existing ADR, surface it explicitly rather
than silently overriding:

> _Contradicts ADR-0007, but worth reopening because…_
