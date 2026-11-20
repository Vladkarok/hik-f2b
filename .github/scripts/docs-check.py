"""Documentation check for hik-f2b. Run it through docs-check.sh.

Reports file:line and a message for each problem, and exits 1 if there is
any. The rules:

  sync       README.md and README.uk.md have the same fenced code blocks (byte
             for byte, in the same order), the same sequence of heading
             levels, tables of the same shape and the same set of inline code
             spans, except where FENCE_TRANSLATIONS and SPAN_TRANSLATIONS below
             say otherwise.
  links      every [text](#anchor) and relative link in a tracked Markdown
             file resolves, with GitHub's anchor rules.
  terms      no term from the "Do not use" column of GLOSSARY.md appears in
             prose. The terms are in .github/docs-terms.txt; every item of the
             column must be listed there, and every listed item must be in the
             column, so the two cannot drift apart.
  steps      a sentence in a numbered list item of the READMEs, RELEASING.md
             and SECURITY.md has at most 20 words. Inline code counts as one
             word, a link as its visible text, a bare URL as one word.
  example    hik-f2b.example.ini has the lines that the deploy files and the
             docs depend on.

Standard library only; Python 3.8 or newer.
"""

import os
import re
import subprocess
import sys
import unicodedata
from urllib.parse import unquote

MAX_STEP_WORDS = 20

# Lines of hik-f2b.example.ini that the deploy files and the docs refer to.
EXAMPLE_INI = "hik-f2b.example.ini"
EXAMPLE_LINES = [
    "password_file = /run/secrets/hik-f2b-router",
    "password_file = /run/secrets/hik-f2b-nvr",
    ";bot_token_file    = /run/secrets/hik-f2b-telegram",
    "ca_file       = /etc/hik-f2b/router-ca.crt",
    ";message_thread_id = 42",
]

# Fenced code blocks that are translated on purpose. Each entry names the
# first line of the English block and lists (English, Ukrainian) line pairs;
# after the pairs are applied, the English block must equal the Ukrainian one
# byte for byte. A change to such a block in one language only still fails.
FENCE_TRANSLATIONS = [
    {
        "why": "the overview diagram is translated",
        "first": 'attacker ──► MikroTik ──dst-nat──► NVR ── writes "Illegal Login" + IP to its log',
        "lines": [
            ('attacker ──► MikroTik ──dst-nat──► NVR ── writes "Illegal Login" + IP to its log',
             'зловмисник ──► MikroTik ──dst-nat──► NVR ── пише "Illegal Login" + IP у журнал'),
            ("                 ▲                                │",
             "                   ▲                                │"),
            ("                 │  REST: add IP to               │  ISAPI: POST /ISAPI/ContentMgmt/logSearch",
             "                   │  REST: додати IP до            │  ISAPI: POST /ISAPI/ContentMgmt/logSearch"),
            ("                 │  address-list, timeout=bantime ▼",
             "                   │  address-list, timeout=bantime ▼"),
            ("                 └──────────────────────────── hik-f2b ──► Telegram (optional)",
             "                   └──────────────────────────── hik-f2b ──► Telegram (за бажанням)"),
        ],
    },
    {
        "why": "the comments in the --check/--dump example are translated",
        "first": "# Every NVR (login, clock, log search), the router and its drop rule,",
        # Lines that start with # may differ; every other line must be equal.
        "comments": True,
    },
    {
        "why": "the placeholder for the version is translated",
        "first": "podman pull ghcr.io/vladkarok/hik-f2b:<new version>",
        "lines": [
            ("podman pull ghcr.io/vladkarok/hik-f2b:<new version>",
             "podman pull ghcr.io/vladkarok/hik-f2b:<нова версія>"),
        ],
    },
]

# Inline code spans that are translated on purpose: (English, Ukrainian, why).
SPAN_TRANSLATIONS = [
    ("<name>_file = /path", "<назва>_file = /шлях", "placeholder words are translated"),
    ("<name> = value", "<назва> = значення", "placeholder words are translated"),
    ("@channelname", "@назва_каналу", "placeholder words are translated"),
]

# Inline code spans that only README.uk.md has: (span, why).
UK_ONLY_SPANS = [
    ("deploy/", "English says \"the deploy files\"; Ukrainian names the directory: «файли з `deploy/`»"),
]

# Files where only some sections are checked for glossary terms: the
# sections of released versions in CHANGELOG.md are kept as they were
# published in the GitHub Releases.
TERMS_ONLY_IN = {"CHANGELOG.md": "unreleased"}

ENGLISH_DOCS = ["README.md", "RELEASING.md", "SECURITY.md", "CHANGELOG.md", "AGENTS.md"]
UKRAINIAN_DOCS = ["README.uk.md"]
STEP_DOCS = ["README.md", "README.uk.md", "RELEASING.md", "SECURITY.md"]
TERMS_FILE = ".github/docs-terms.txt"

problems = []


def report(path, line, message):
    problems.append((path, line, message))


def read(path):
    with open(path, encoding="utf-8", newline="") as f:
        return f.read().replace("\r\n", "\n")


def tracked_files():
    out = subprocess.run(["git", "ls-files", "-z"], check=True, stdout=subprocess.PIPE).stdout
    return [p for p in out.decode("utf-8").split("\0") if p]


class Doc:
    """A Markdown file split into fenced blocks and prose.

    prose is the text outside fenced blocks, with the same line numbers:
    fenced lines are empty, and each inline code span is replaced by the word
    CODE (keeping the line breaks inside it).
    """

    FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
    SPAN = re.compile(r"(?<!`)(`+)(?!`)(.+?)(?<!`)\1(?!`)", re.S)

    def __init__(self, path):
        self.path = path
        self.text = read(path)
        lines = self.text.split("\n")
        self.fences = []  # (line, info, content)
        outside = []
        fence = None
        for i, line in enumerate(lines, 1):
            m = self.FENCE.match(line)
            if fence is None and m:
                fence = (m.group(1), i, m.group(2).strip(), [])
                outside.append("")
            elif fence is not None:
                if line.strip().startswith(fence[0][0] * len(fence[0])) and line.strip().strip(fence[0][0]) == "":
                    self.fences.append((fence[1], fence[2], "\n".join(fence[3])))
                    fence = None
                else:
                    fence[3].append(line)
                outside.append("")
            else:
                outside.append(line)
        if fence is not None:
            report(path, fence[1], "fenced code block is not closed")
        raw = "\n".join(outside)
        self.spans = []  # (line, content)
        # Spans do not cross a blank line.
        parts = re.split(r"(\n[ \t]*\n)", raw)
        pos_line = 1
        prose_parts = []
        for part in parts:
            def repl(m, base=pos_line, part=part):
                line = base + part.count("\n", 0, m.start())
                content = m.group(2)
                if content.startswith(" ") and content.endswith(" ") and content.strip():
                    content = content[1:-1]
                self.spans.append((line, content.replace("\n", " ")))
                return "CODE" + "\n" * m.group(0).count("\n")
            prose_parts.append(self.SPAN.sub(repl, part))
            pos_line += part.count("\n")
        self.prose = "".join(prose_parts)
        self.prose_lines = self.prose.split("\n")
        self.headings = []  # (line, level, text, anchor)
        seen = {}
        for i, line in enumerate(outside, 1):
            m = re.match(r"^ {0,3}(#{1,6})[ \t]+(.*?)[ \t]*#*[ \t]*$", line)
            if m:
                slug = github_slug(m.group(2))
                n = seen.get(slug, 0)
                seen[slug] = n + 1
                anchor = slug if n == 0 else "%s-%d" % (slug, n)
                self.headings.append((i, len(m.group(1)), m.group(2), anchor))
        self.anchors = {h[3] for h in self.headings}

    def tables(self):
        """Yields (line, [columns per row]) for each table."""
        rows, start = [], None
        for i, line in enumerate(self.prose_lines + [""], 1):
            if line.lstrip().startswith("|"):
                if start is None:
                    start = i
                cells = re.split(r"(?<!\\)\|", line.strip())
                rows.append(len(cells) - 2)
            elif start is not None:
                yield start, rows
                rows, start = [], None

    def section(self, anchor):
        """Line range [first, last] of the section with this anchor.

        The pseudo-anchor "intro" is the text before the first heading of
        level 2."""
        if anchor == "intro":
            for line, level, _, _ in self.headings:
                if level == 2:
                    return 1, line - 1
            return 1, len(self.prose_lines)
        for k, (line, level, _, a) in enumerate(self.headings):
            if a == anchor:
                end = len(self.prose_lines)
                for line2, level2, _, _ in self.headings[k + 1:]:
                    if level2 <= level:
                        end = line2 - 1
                        break
                return line, end
        return None


def github_slug(heading):
    text = re.sub(r"`([^`]*)`", r"\1", heading)
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"<[^>]+>", "", text)
    text = text.strip().lower()
    out = []
    for ch in text:
        cat = unicodedata.category(ch)
        if ch in "-_ " or cat[0] in "LN" or cat in ("Mn", "Mc", "Pc"):
            out.append("-" if ch == " " else ch)
    return "".join(out)


# ---------------------------------------------------------------- sync

def check_sync(en, uk):
    # Fenced blocks.
    if len(en.fences) != len(uk.fences):
        report(uk.path, 1, "%d fenced code blocks, %s has %d" % (len(uk.fences), en.path, len(en.fences)))
    for (eline, einfo, etext), (uline, uinfo, utext) in zip(en.fences, uk.fences):
        expected = etext
        for t in FENCE_TRANSLATIONS:
            if etext.split("\n", 1)[0] == t["first"]:
                lines = etext.split("\n")
                if t.get("comments"):
                    ulines = utext.split("\n")
                    if len(ulines) == len(lines):
                        expected = "\n".join(u if e.startswith("#") and u.startswith("#") else e
                                             for e, u in zip(lines, ulines))
                else:
                    pairs = dict(t["lines"])
                    expected = "\n".join(pairs.get(l, l) for l in lines)
                break
        if einfo != uinfo or expected != utext:
            report(uk.path, uline, "fenced code block differs from the one at %s:%d" % (en.path, eline))
    # Headings.
    elevels = [h[1] for h in en.headings]
    ulevels = [h[1] for h in uk.headings]
    for k, (eh, uh) in enumerate(zip(en.headings, uk.headings)):
        if eh[1] != uh[1]:
            report(uk.path, uh[0], "heading level %d, %s:%d has level %d" % (uh[1], en.path, eh[0], eh[1]))
            break
    if len(elevels) != len(ulevels):
        report(uk.path, 1, "%d headings, %s has %d" % (len(ulevels), en.path, len(elevels)))
    # Tables.
    et, ut = list(en.tables()), list(uk.tables())
    if len(et) != len(ut):
        report(uk.path, 1, "%d tables, %s has %d" % (len(ut), en.path, len(et)))
    for (eline, erows), (uline, urows) in zip(et, ut):
        if erows != urows:
            report(uk.path, uline, "table shape %s differs from %s:%d (%s), as rows x columns"
                   % (shape(urows), en.path, eline, shape(erows)))
    # Inline code spans.
    to_uk = {e: u for e, u, _ in SPAN_TRANSLATIONS}
    espans = {}
    for line, s in en.spans:
        espans.setdefault(to_uk.get(s, s), line)
    uspans = {}
    for line, s in uk.spans:
        uspans.setdefault(s, line)
    for s in sorted(set(espans) - set(uspans)):
        report(en.path, espans[s], "inline code `%s` is not in %s" % (s, uk.path))
    uk_only = {s for s, _ in UK_ONLY_SPANS}
    for s in sorted(set(uspans) - set(espans) - uk_only):
        report(uk.path, uspans[s], "inline code `%s` is not in %s" % (s, en.path))
    for s in sorted(uk_only - set(uspans)):
        report(".github/scripts/docs-check.py", 1, "UK_ONLY_SPANS entry `%s` is not used" % s)
    for e, u, _ in SPAN_TRANSLATIONS:
        if u not in uspans:
            report(".github/scripts/docs-check.py", 1, "SPAN_TRANSLATIONS entry `%s` is not used" % e)
    for t in FENCE_TRANSLATIONS:
        if not any(f[2].split("\n", 1)[0] == t["first"] for f in en.fences):
            report(".github/scripts/docs-check.py", 1, "FENCE_TRANSLATIONS entry '%s' is not used" % t["why"])


def shape(rows):
    cols = sorted(set(rows))
    return "%dx%s" % (len(rows), "/".join(map(str, cols)))


# ---------------------------------------------------------------- links

LINK = re.compile(r"!?\[(?:[^\]\\]|\\.)*\]\(\s*<?([^)\s>]*)>?(?:\s+\"[^\"]*\")?\s*\)")
REFDEF = re.compile(r"^ {0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s|$)")


def check_links(docs, files):
    dirs = set()
    for f in files:
        parts = f.split("/")
        for k in range(1, len(parts)):
            dirs.add("/".join(parts[:k]))
    for doc in docs.values():
        for i, line in enumerate(doc.prose_lines, 1):
            targets = [m.group(1) for m in LINK.finditer(line)]
            m = REFDEF.match(line)
            if m:
                targets.append(m.group(1))
            for target in targets:
                check_link(doc, i, target, docs, files, dirs)


def check_link(doc, line, target, docs, files, dirs):
    if not target or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", target) or target.startswith("//"):
        return
    path, _, anchor = target.partition("#")
    anchor = unquote(anchor)
    if path:
        base = os.path.dirname(doc.path)
        full = os.path.normpath(os.path.join(base, unquote(path))).replace("\\", "/")
        if full not in files and full not in dirs:
            report(doc.path, line, "link to %s: no such file in the repository" % path)
            return
        if not anchor:
            return
        if not full.endswith(".md"):
            return
        if full not in docs:
            docs[full] = Doc(full)
        target_doc = docs[full]
    else:
        target_doc = doc
    if anchor and anchor not in target_doc.anchors:
        report(doc.path, line, "link to #%s: no such heading in %s" % (anchor, target_doc.path))


# ---------------------------------------------------------------- terms

def glossary_items():
    """Yields (row term, item) for each item of the "Do not use" column."""
    doc = read("GLOSSARY.md").split("\n")
    header = None
    for line in doc:
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in re.split(r"(?<!\\)\|", line.strip())[1:-1]]
        if header is None:
            header = cells
            col = next(k for k, c in enumerate(cells) if c.startswith("Do not use"))
            continue
        if set(cells[0]) <= set("-: "):
            continue
        for item in split_items(cells[col]):
            yield cells[0], item


def split_items(cell):
    """Splits at , and ; outside parentheses."""
    items, cur, depth = [], "", 0
    for ch in cell:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch in ",;" and depth == 0:
            items.append(cur.strip())
            cur = ""
        else:
            cur += ch
    items.append(cur.strip())
    return [i for i in items if i]


def load_terms():
    """Parses .github/docs-terms.txt. Returns the list of checked terms."""
    terms = []
    listed = set()
    for n, raw in enumerate(read(TERMS_FILE).split("\n"), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = [f.strip() for f in line.split(" | ")]
        if len(fields) < 4:
            report(TERMS_FILE, n, "expected: row | item | en, uk or skip | regex or reason [| except ...]")
            continue
        row, item, kind, rest = fields[0], fields[1], fields[2], fields[3:]
        listed.add((row, item))
        if kind == "skip":
            continue
        if kind not in ("en", "uk"):
            report(TERMS_FILE, n, "language must be en, uk or skip, not '%s'" % kind)
            continue
        try:
            regex = re.compile(rest[0], re.I)
        except re.error as e:
            report(TERMS_FILE, n, "invalid regex: %s" % e)
            continue
        excepts = []
        for f in rest[1:]:
            if not f.startswith("except "):
                report(TERMS_FILE, n, "unknown field '%s'" % f)
                continue
            for place in f[len("except "):].split():
                file, _, anchor = place.partition("#")
                excepts.append((file, anchor))
        terms.append({"line": n, "row": row, "item": item, "lang": kind, "regex": regex, "except": excepts})
    glossary = set(glossary_items())
    for row, item in sorted(glossary - listed):
        report(TERMS_FILE, 1, "GLOSSARY.md row '%s' forbids '%s'; list it here, as checked or skipped" % (row, item))
    for row, item in sorted(listed - glossary):
        report(TERMS_FILE, 1, "'%s' / '%s' is not in the \"Do not use\" column of GLOSSARY.md" % (row, item))
    return terms


def check_terms(docs):
    terms = load_terms()
    for lang, names in (("en", ENGLISH_DOCS), ("uk", UKRAINIAN_DOCS)):
        for name in names:
            if name not in docs:
                continue
            doc = docs[name]
            only = None
            if name in TERMS_ONLY_IN:
                only = doc.section(TERMS_ONLY_IN[name])
                if only is None:
                    continue
            for term in terms:
                if term["lang"] != lang:
                    continue
                allowed = []
                for file, anchor in term["except"]:
                    if file != name:
                        continue
                    r = doc.section(anchor)
                    if r is None:
                        report(TERMS_FILE, term["line"], "no section #%s in %s" % (anchor, name))
                    else:
                        allowed.append(r)
                for i, line in enumerate(prose_for_terms(doc), 1):
                    m = term["regex"].search(line)
                    if only is not None and not only[0] <= i <= only[1]:
                        continue
                    if m and not any(a <= i <= b for a, b in allowed):
                        report(name, i, "'%s': GLOSSARY.md says to use '%s' instead (%s:%d)"
                               % (m.group(0), term["row"], TERMS_FILE, term["line"]))


def prose_for_terms(doc):
    out = []
    for line in doc.prose_lines:
        line = re.sub(r"\]\([^)]*\)", "]", line)       # link targets
        line = re.sub(r"https?://\S+", "URL", line)     # bare URLs
        line = re.sub(r"<!--.*?-->", "", line)
        out.append(line)
    return out


# ---------------------------------------------------------------- steps

ITEM = re.compile(r"^(\s*)(\d+)[.)]\s+")
BULLET = re.compile(r"^\s*([-*+]|\d+[.)])\s+")


def check_steps(doc):
    lines = doc.prose_lines
    i = 0
    while i < len(lines):
        m = ITEM.match(lines[i])
        if not m:
            i += 1
            continue
        indent = len(m.group(0))
        item = [(i + 1, lines[i][len(m.group(0)):])]
        j = i + 1
        while j < len(lines):
            line = lines[j]
            if not line.strip():
                # A blank line ends the item unless an indented paragraph follows.
                k = j + 1
                while k < len(lines) and not lines[k].strip():
                    k += 1
                if k < len(lines) and leading(lines[k]) >= indent and not BULLET.match(lines[k]):
                    j = k
                    continue
                break
            if BULLET.match(line) or leading(line) < 1:
                break
            item.append((j + 1, line.strip()))
            j += 1
        check_sentences(doc.path, item)
        i = j if j > i else i + 1


def leading(line):
    return len(line) - len(line.lstrip(" "))


def check_sentences(path, item):
    # Words with their line numbers.
    words = []
    for line, text in item:
        text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", text)
        text = re.sub(r"https?://\S+", "URL", text)
        for w in text.split():
            words.append((line, w))
    sentence = []
    for k, (line, w) in enumerate(words):
        sentence.append((line, w))
        nxt = words[k + 1][1] if k + 1 < len(words) else None
        if re.search(r"[.!?][\"'»”)*]*$", w) and (nxt is None or not nxt[0].islower()):
            flush(path, sentence)
            sentence = []
    flush(path, sentence)


def flush(path, sentence):
    counted = [w for _, w in sentence if re.search(r"\w", w)]
    if len(counted) > MAX_STEP_WORDS:
        report(path, sentence[0][0], "a sentence in a numbered step has %d words, at most %d: '%s ...'"
               % (len(counted), MAX_STEP_WORDS, " ".join(w for _, w in sentence[:6])))


# ---------------------------------------------------------------- example

def check_example():
    lines = read(EXAMPLE_INI).split("\n")
    for want in EXAMPLE_LINES:
        if want not in lines:
            report(EXAMPLE_INI, 1, "line '%s' is missing; deploy files and docs refer to it" % want)


def main():
    root = subprocess.run(["git", "rev-parse", "--show-toplevel"], check=True,
                          stdout=subprocess.PIPE).stdout.decode("utf-8").strip()
    os.chdir(root)
    files = set(tracked_files())
    docs = {p: Doc(p) for p in sorted(files) if p.endswith(".md")}
    check_sync(docs["README.md"], docs["README.uk.md"])
    check_links(docs, files)
    check_terms(docs)
    for name in STEP_DOCS:
        check_steps(docs[name])
    check_example()
    for path, line, message in sorted(set(problems)):
        print("%s:%d: %s" % (path, line, message))
    if problems:
        print("docs-check: %d problem(s)" % len(set(problems)), file=sys.stderr)
        return 1
    print("docs-check: ok (%d Markdown files)" % len(docs))
    return 0


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    sys.exit(main())
