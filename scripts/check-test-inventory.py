#!/usr/bin/env python3
"""No hidden tests (criterion C1a of the 100% plan).

A test that never runs proves nothing and looks like coverage. This script fails when it finds:

* a test with ``#[ignore]`` or ``#[cfg_attr(<condition>, ignore)]``, except in
  ``tests/testenv_*.rs`` (the real-network environment runs those) where the attribute must
  carry its reason (``#[ignore = "..."]``);
* a commented-out ``#[test]`` / ``#[tokio::test]``;
* a ``*_test.rs`` file under a crate's ``src/`` that no ``mod`` declaration (or ``#[path]``)
  compiles;
* a test, or a ``mod`` holding tests, behind a platform ``cfg`` (``windows``, ``unix``,
  ``target_os``, ``target_family``, ``target_arch``, ``target_env``), so it silently does not
  exist on some platform;

* an integration test target with ``required-features`` (a ``[[test]]`` of a ``Cargo.toml``) that
  no ``cargo test`` command in ``.github/workflows/cargo.yml`` runs: one that selects the package
  (``--package`` / ``-p``, or ``--workspace``), turns every required feature on (the package's
  default features unless ``--no-default-features``, ``--features``, ``--all-features``, each
  feature's own implications) and runs the target (no target selection, ``--tests``, or
  ``--test <name>``) with no test name filter; cargo skips such a target silently otherwise;

unless ``docs/test-exclusions.md`` lists it with a reason and the test that covers the same
behaviour. An exclusion row that no longer matches anything also fails, so the list cannot go
stale.

It also checks every test that ``docs/conformance.md`` and ``docs/conformance/*.md`` name in
their "Test" column exists (criterion C5).

With ``--check`` (how CI runs it) it also checks the clause audit (``docs/conformance/audit/*.md``):
every backticked name in the Test cell of a MUST or SHOULD row must name something in the tree, so
a renamed or deleted test cannot stay cited as evidence. A name is the last ``::`` segment of the
backticked text (``name``, ``file.rs::name``, ``mod::tests``; a trailing ``(...)`` is dropped) when
it is a snake_case identifier with an underscore; it is found when it is a ``fn``, a module (a
``mod`` declaration or a ``.rs`` file stem, test files included), a fuzz target (a file under a
``fuzz_targets`` directory) or a struct field. Backticked text that is not such an identifier
(paths, SDP lines, constants, short variable names such as ``hd`` or ``prov``) is not a test name
and is not checked. A ``dir/file.rs::name`` whose name is a ``fn`` only in files of another name is reported
too (the directory is not compared: cells abbreviate it).

Usage: ``python3 scripts/check-test-inventory.py [--list | --check]``. ``--list`` prints every
finding, excluded or not, in the exclusion table's format.
"""

from __future__ import annotations

import os
import re
import shlex
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXCLUSIONS = ROOT / "docs" / "test-exclusions.md"
CARGO_WORKFLOW = Path(".github") / "workflows" / "cargo.yml"
CONFORMANCE = [ROOT / "docs" / "conformance.md", *sorted((ROOT / "docs" / "conformance").glob("*.md"))]

# Directories that hold no tests of the workspace: build output, fuzz crates (their own
# workspaces, no tests), vendored or generated trees.
SKIP_DIRS = {"target", ".git", "fuzz", "node_modules", "artifacts", "corpus"}

TEST_ATTR = re.compile(r"#\[\s*(?:tokio::test|async_std::test|test|rstest|test_case)\b[^\]]*\]")
IGNORE_ATTR = re.compile(r"#\[\s*ignore\s*(=\s*\"(?P<reason>[^\"]*)\")?\s*\]")
# `#[cfg_attr(windows, ignore = "...")]`: ignored where the condition holds (shown as ignored
# there, not as passed), so listed like a plain `#[ignore]`.
CFG_ATTR_IGNORE = re.compile(r"#\[\s*cfg_attr\s*\(.*,\s*ignore\s*(=\s*\"(?P<reason>[^\"]*)\")?\s*,?\s*\)\s*\]")
FN_DEF = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)")
MOD_DECL = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*;")
PATH_ATTR = re.compile(r"#\[\s*path\s*=\s*\"(?P<path>[^\"]+)\"\s*\]")
COMMENTED_TEST = re.compile(r"^\s*(?://+|/\*+|\*)\s*#\[\s*(?:tokio::test|async_std::test|test)\b")
PLATFORM_CFG = re.compile(r"#\[\s*cfg\s*\((?P<expr>.*)\)\s*\]")
PLATFORM_WORDS = re.compile(r"\b(windows|unix|target_os|target_family|target_arch|target_env)\b")


@dataclass(frozen=True)
class Finding:
    kind: str  # ignored | commented | orphan | platform | feature-gated
    path: str  # relative to the repository root
    test: str  # the test (or module / "*")
    detail: str = ""

    def key(self) -> tuple[str, str, str]:
        return (self.kind, self.path, self.test)


def rust_files() -> list[Path]:
    out = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            if name.endswith(".rs"):
                out.append(Path(dirpath) / name)
    return sorted(out)


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def attributes_then_item(lines: list[str], start: int) -> tuple[list[str], int]:
    """The attribute lines from `start` on and the index of the first line that is not an
    attribute, a comment or blank (the item they apply to)."""
    attrs = []
    i = start
    while i < len(lines):
        stripped = lines[i].strip()
        if stripped.startswith("#["):
            # An attribute may span lines; join until its brackets balance.
            text = stripped
            depth = text.count("[") - text.count("]")
            while depth > 0 and i + 1 < len(lines):
                i += 1
                text += " " + lines[i].strip()
                depth = text.count("[") - text.count("]")
            attrs.append(text)
        elif stripped == "" or stripped.startswith("//"):
            pass
        else:
            return attrs, i
        i += 1
    return attrs, i


def scan_file(path: Path, findings: list[Finding], tests: dict[str, set[str]]) -> None:
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    relpath = rel(path)
    is_testenv = relpath.startswith("tests/testenv_") and relpath.endswith(".rs")
    # Lines inside /* ... */ block comments (not nested; strings are not parsed, which is fine
    # for test code): a #[test] there is commented out like a `// #[test]`.
    in_block = []
    depth = 0
    for line in lines:
        starts_inside = depth > 0
        depth += len(re.findall(r"/\*", line)) - len(re.findall(r"\*/", line))
        depth = max(depth, 0)
        in_block.append(starts_inside or (depth > 0 and line.strip().startswith("/*")))
    i = 0
    while i < len(lines):
        line = lines[i]
        if in_block[i] and not COMMENTED_TEST.match(line):
            if TEST_ATTR.search(line):
                name = "*"
                for follow in lines[i + 1 : i + 6]:
                    m = re.search(r"fn\s+([A-Za-z_][A-Za-z0-9_]*)", follow)
                    if m:
                        name = m.group(1)
                        break
                findings.append(Finding("commented", relpath, name, f"line {i + 1}, in a block comment"))
            i += 1
            continue
        if COMMENTED_TEST.match(line):
            name = "*"
            for follow in lines[i + 1 : i + 4]:
                m = re.search(r"fn\s+([A-Za-z_][A-Za-z0-9_]*)", follow)
                if m:
                    name = m.group(1)
                    break
            findings.append(Finding("commented", relpath, name, f"line {i + 1}"))
            i += 1
            continue
        if line.strip().startswith("#["):
            attrs, item = attributes_then_item(lines, i)
            joined = " ".join(attrs)
            item_line = lines[item] if item < len(lines) else ""
            fn = FN_DEF.match(item_line)
            mod = MOD_DECL.match(item_line) or re.match(
                r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\{", item_line
            )
            platform = [
                m.group("expr")
                for m in (PLATFORM_CFG.search(a) for a in attrs)
                if m and PLATFORM_WORDS.search(m.group("expr"))
            ]
            if fn and TEST_ATTR.search(joined):
                name = fn.group("name")
                tests.setdefault(name, set()).add(relpath)
                ignore = IGNORE_ATTR.search(joined) or CFG_ATTR_IGNORE.search(joined)
                if ignore:
                    if not (is_testenv and ignore.group("reason")):
                        findings.append(Finding("ignored", relpath, name, ignore.group(0)))
                if platform:
                    findings.append(Finding("platform", relpath, name, "; ".join(platform)))
            elif mod and platform and ("test" in mod.group("name") or "cfg(test" in joined):
                findings.append(Finding("platform", relpath, "mod " + mod.group("name"), "; ".join(platform)))
            i = max(item, i + 1)
            continue
        i += 1


def declared_modules(files: list[Path]) -> tuple[set[tuple[str, str]], set[str]]:
    """(directory, module name) pairs every `mod x;` declares, and every `#[path]` target."""
    mods: set[tuple[str, str]] = set()
    paths: set[str] = set()
    for path in files:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        # A `mod x;` in foo/mod.rs or foo/lib.rs (or a crate root) looks in foo/; in foo/bar.rs
        # it looks in foo/bar/.
        if path.name in ("mod.rs", "lib.rs", "main.rs"):
            base = path.parent
        else:
            base = path.parent / path.stem
        for n, line in enumerate(lines):
            m = MOD_DECL.match(line)
            if m:
                mods.add((rel(base) if base != ROOT else ".", m.group("name")))
                # A `#[path]` on the line(s) before applies to this declaration.
                for back in lines[max(0, n - 3) : n]:
                    p = PATH_ATTR.search(back)
                    if p:
                        paths.add((path.parent / p.group("path")).resolve().as_posix())
    return mods, paths


def orphan_test_files(files: list[Path], findings: list[Finding]) -> None:
    mods, paths = declared_modules(files)
    for path in files:
        relpath = rel(path)
        if not path.stem.endswith("_test") or "/src/" not in "/" + relpath:
            continue
        parent = rel(path.parent) if path.parent != ROOT else "."
        if (parent, path.stem) in mods or path.resolve().as_posix() in paths:
            continue
        findings.append(Finding("orphan", relpath, "*", "no `mod` compiles this file"))


@dataclass(frozen=True)
class GatedTest:
    """An integration test target that exists only with some features: a ``[[test]]`` with
    ``required-features``, or a test file whose crate-level ``#![cfg(...)]`` names a feature
    (compiled without it, the target builds and runs 0 tests)."""

    package: str
    name: str
    path: str  # the test's source, relative to the repository root
    required: frozenset[str]
    defaults: frozenset[str]
    features: dict  # the package's [features] table
    cfg: str | None = None  # the crate-level cfg predicate, when it names a feature

    def holds(self, enabled: set[str]) -> bool:
        return self.required <= enabled and (self.cfg is None or cfg_holds(self.cfg, enabled))

    def needs_a_feature_off(self) -> bool:
        return self.cfg is not None and "not" in cfg_tokens(self.cfg)

    def what(self) -> str:
        parts = []
        if self.required:
            parts.append(f"needs {', '.join(sorted(self.required))}")
        if self.cfg is not None:
            parts.append(f"#![cfg({self.cfg})]")
        return " and ".join(parts)


CRATE_CFG = re.compile(r"^\s*#!\[\s*cfg\s*\((?P<expr>.*)\)\s*\]\s*$")


def cfg_tokens(expr: str) -> list[str]:
    return re.findall(r'"[^"]*"|[A-Za-z_][A-Za-z0-9_]*|[(),=]', expr)


def cfg_holds(expr: str, enabled: set[str]) -> bool:
    """Evaluates a cfg predicate for the features `enabled`. A predicate that is not about
    features (`unix`, `target_os = "linux"`) counts as true: platforms are the `platform` kind's
    business, and CI's platforms are not modelled here."""
    tokens = cfg_tokens(expr)
    at = 0

    def predicate() -> bool:
        nonlocal at
        word = tokens[at]
        at += 1
        if word in ("all", "any", "not") and at < len(tokens) and tokens[at] == "(":
            at += 1
            values = []
            while tokens[at] != ")":
                values.append(predicate())
                if tokens[at] == ",":
                    at += 1
            at += 1
            if word == "all":
                return all(values)
            if word == "any":
                return any(values)
            return not values[0]
        if at < len(tokens) and tokens[at] == "=":
            value = tokens[at + 1].strip('"')
            at += 2
            return value in enabled if word == "feature" else True
        return True

    try:
        return predicate()
    except IndexError:
        return True


def crate_cfg(source: Path) -> str | None:
    """The crate-level `#![cfg(...)]` of a test file, when it names a feature (several are
    joined with `all`)."""
    try:
        lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    found = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        m = CRATE_CFG.match(line)
        if m:
            found.append(m.group("expr").strip())
            continue
        if stripped.startswith("#!["):
            continue
        break
    found = [f for f in found if re.search(r"\bfeature\s*=", f)]
    if not found:
        return None
    return found[0] if len(found) == 1 else f"all({', '.join(found)})"


def root_package(root: Path) -> str | None:
    try:
        return tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8")).get("package", {}).get("name")
    except (OSError, tomllib.TOMLDecodeError):
        return None


def gated_tests(root: Path) -> list[GatedTest]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        if "Cargo.toml" not in filenames:
            continue
        manifest = Path(dirpath) / "Cargo.toml"
        try:
            data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError):
            continue
        package = data.get("package", {}).get("name")
        if not package:
            continue
        features = data.get("features", {})
        targets = {}
        for target in data.get("test", []):
            source = Path(dirpath) / target.get("path", f"tests/{target['name']}.rs")
            targets[source.resolve()] = (target["name"], target.get("required-features", []))
        if data.get("package", {}).get("autotests", True):
            for source in sorted((Path(dirpath) / "tests").glob("*.rs")):
                targets.setdefault(source.resolve(), (source.stem, []))
        for source, (name, required) in targets.items():
            cfg = crate_cfg(source)
            if not required and cfg is None:
                continue
            out.append(
                GatedTest(
                    package=package,
                    name=name,
                    path=source.relative_to(root.resolve()).as_posix(),
                    required=frozenset(required),
                    defaults=frozenset(features.get("default", [])),
                    features=features,
                    cfg=cfg,
                )
            )
    return sorted(out, key=lambda t: (t.package, t.name))


JOB_KEY = re.compile(r"^  (?P<name>[A-Za-z0-9_-]+):\s*$")
MATRIX_LIST = re.compile(r"^\s+(?P<key>[A-Za-z0-9_-]+):\s*\[(?P<values>[^\]]*)\]\s*$")
INCLUDE_ITEM = re.compile(r"^(?P<indent>\s+)- (?P<key>[A-Za-z0-9_-]+):\s*(?P<value>.*)$")
ITEM_FIELD = re.compile(r"^(?P<indent>\s+)(?P<key>[A-Za-z0-9_-]+):\s*(?P<value>.*)$")


def unquote_yaml(value: str) -> str:
    value = re.sub(r"\s+#.*$", "", value.strip())
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def matrix_values(job: list[str]) -> dict[str, list[str]]:
    """A job's matrix values by key: `key: [ a, b ]` lists and the fields of `include:` items.
    An include item without the key gives an empty value."""
    values: dict[str, list[str]] = {}
    items: list[dict[str, str]] = []
    in_matrix = False
    matrix_indent = 0
    item_indent = None
    for line in job:
        stripped = line.strip()
        if stripped.startswith("matrix:"):
            in_matrix = True
            matrix_indent = len(line) - len(line.lstrip())
            continue
        if not in_matrix or not stripped or stripped.startswith("#"):
            continue
        if len(line) - len(line.lstrip()) <= matrix_indent:
            in_matrix = False
            continue
        m = MATRIX_LIST.match(line)
        if m and item_indent is None:
            values[m.group("key")] = [unquote_yaml(v) for v in m.group("values").split(",") if v.strip()]
            continue
        m = INCLUDE_ITEM.match(line)
        if m:
            item_indent = len(m.group("indent")) + 2
            items.append({m.group("key"): unquote_yaml(m.group("value"))})
            continue
        m = ITEM_FIELD.match(line)
        if m and items and len(m.group("indent")) == item_indent:
            items[-1][m.group("key")] = unquote_yaml(m.group("value"))
    for item in items:
        for key in {k for i in items for k in i}:
            values.setdefault(key, [])
        for key in {k for i in items for k in i}:
            values[key].append(item.get(key, ""))
    return values


def cargo_test_commands(workflow_text: str) -> list[list[str]]:
    """The arguments after each `cargo test` of a workflow (shell continuations joined, the
    command cut at `;`, `&&`, `||`, `|`, `>`, a quote), once per value of each matrix key it
    names (`${{ matrix.key }}`, from its job's matrix). Any other GitHub expression is left out:
    it cannot be read here."""
    jobs: list[list[str]] = [[]]
    for line in workflow_text.splitlines():
        if JOB_KEY.match(line):
            jobs.append([])
        jobs[-1].append(line)
    commands = []
    for job in jobs:
        matrix = matrix_values(job)
        text = re.sub(r"\\\n\s*", " ", "\n".join(job))
        for line in text.splitlines():
            for m in re.finditer(r"\bcargo\s+test\b(?P<rest>[^\n]*)", line):
                rest = re.split(r";|&&|\|\||\||>|'|\"", m.group("rest"))[0]
                variants = [rest]
                for key in dict.fromkeys(re.findall(r"\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}", rest)):
                    pattern = re.compile(r"\$\{\{\s*matrix\." + re.escape(key) + r"\s*\}\}")
                    choices = matrix.get(key) or [" "]
                    variants = [pattern.sub(lambda _: c, v) for v in variants for c in choices]
                for variant in variants:
                    variant = re.sub(r"\$\{\{[^}]*\}\}", " ", variant)
                    try:
                        commands.append(shlex.split(variant))
                    except ValueError:
                        continue
    return commands


def enabled_features(test: GatedTest, chosen: set[str], defaults: bool, every: bool) -> set[str]:
    if every:
        return set(test.features)
    pending = list(chosen | (set(test.defaults) if defaults else set()))
    enabled: set[str] = set()
    while pending:
        feature = pending.pop()
        if feature in enabled:
            continue
        enabled.add(feature)
        for implied in test.features.get(feature, []):
            if "/" not in implied and not implied.startswith("dep:"):
                pending.append(implied)
    return enabled


def command_runs(args: list[str], test: GatedTest, root_package: str | None = "rtci") -> bool:
    """Whether `cargo test <args>`, run at the repository root, runs `test` whole.

    Features are those of the command line, the package's defaults and their implications.
    Feature unification across the build (another package, or a dev-dependency, turning one of
    this package's features on) is not modelled: for a target that needs a feature on, that can
    only make this check stricter than cargo; for one that needs a feature OFF (`not(...)`),
    only a command that selects the package by name (`-p`, not `--workspace`) counts, since a
    workspace build turns on what any member asks for."""
    packages: set[str] = set()
    workspace = False
    chosen: set[str] = set()
    defaults = True
    every = False
    tests: set[str] = set()
    all_tests = False
    other_targets = False
    i = 0
    while i < len(args):
        arg = args[i]
        value = args[i + 1] if i + 1 < len(args) else ""
        if arg == "--":
            # Arguments for the test harness: a name filter runs part of each target.
            if any(not a.startswith("-") for a in args[i + 1 :]):
                return False
            break
        if arg in ("-p", "--package"):
            packages.add(value)
            i += 2
            continue
        if arg.startswith("--package="):
            packages.add(arg.split("=", 1)[1])
        elif arg in ("--workspace", "--all"):
            workspace = True
        elif arg in ("-F", "--features"):
            chosen |= {f for f in re.split(r"[,\s]+", value) if f}
            i += 2
            continue
        elif arg.startswith("--features="):
            chosen |= {f for f in re.split(r"[,\s]+", arg.split("=", 1)[1]) if f}
        elif arg == "--all-features":
            every = True
        elif arg == "--no-default-features":
            defaults = False
        elif arg == "--test":
            tests.add(value)
            i += 2
            continue
        elif arg == "--tests":
            all_tests = True
        elif arg in ("--lib", "--bins", "--bin", "--examples", "--example", "--benches", "--bench", "--doc"):
            other_targets = True
        elif arg in ("--target", "--target-dir", "--manifest-path", "--exclude", "--profile", "-j", "--jobs"):
            i += 2
            continue
        elif not arg.startswith("-"):
            # A test name filter before `--`.
            return False
        i += 1
    if test.needs_a_feature_off():
        if test.package not in packages and not (not packages and not workspace and test.package == root_package):
            return False
    elif not (test.package in packages or workspace or (not packages and test.package == root_package)):
        return False
    # `pkg/feature` turns a feature of that package on; a bare name, one of the selected ones.
    own = {f.split("/", 1)[1] for f in chosen if f.startswith(test.package + "/")}
    own |= {f for f in chosen if "/" not in f}
    if not test.holds(enabled_features(test, own, defaults, every)):
        return False
    if tests:
        return test.name in tests
    return all_tests or not other_targets


def feature_gated_findings(root: Path, findings: list[Finding]) -> None:
    workflow = root / CARGO_WORKFLOW
    text = workflow.read_text(encoding="utf-8") if workflow.exists() else ""
    commands = cargo_test_commands(text)
    top = root_package(root)
    for test in gated_tests(root):
        if not any(command_runs(args, test, top) for args in commands):
            findings.append(
                Finding(
                    "feature-gated",
                    test.path,
                    "*",
                    f"test target {test.name} of {test.package} ({test.what()}):"
                    f" no cargo test in {CARGO_WORKFLOW.as_posix()} runs it with its features",
                )
            )


def parse_table(path: Path) -> list[list[str]]:
    rows = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line.startswith("|") or re.match(r"^\|\s*:?-{3,}", line):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        rows.append(cells)
    return rows


def unquote(cell: str) -> str:
    return cell.strip().strip("`").strip()


def backticked(cell: str) -> list[str]:
    return re.findall(r"`([^`]+)`", cell)


def test_exists(ref: str, tests: dict[str, set[str]]) -> bool:
    """`name`, `path.rs::name`, or a test file `path.rs`, names a test (or a file holding tests)
    the scan found. A path may be given from any directory down (`tests/x.rs`, `x_test.rs`)."""
    if ref.endswith(".rs"):
        return any(p == ref or p.endswith("/" + ref) for paths in tests.values() for p in paths)
    if "::" in ref:
        file, _, name = ref.rpartition("::")
        return name in tests and any(p == file or p.endswith("/" + file) for p in tests[name])
    return ref in tests


AUDIT_LEVELS = re.compile(r"^(MUST|SHALL|REQUIRED|SHOULD|RECOMMENDED|NOT RECOMMENDED)\b")
AUDIT_NAME = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)+")
FIELD_DEF = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?P<name>[a-z_][a-z0-9_]*)\s*:\s*[A-Za-z(&\[]")
MOD_ANY = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)")


def tree_names(root: Path) -> tuple[dict[str, set[str]], set[str]]:
    """Every `fn` in the tree's Rust sources (name -> files, fuzz crates included), and the other
    names an audit Test cell may cite: modules (declared or by file stem), fuzz targets, fields."""
    fns: dict[str, set[str]] = {}
    other: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {"target", ".git", "node_modules"} and not d.startswith(".")]
        for name in filenames:
            if not name.endswith(".rs"):
                continue
            path = Path(dirpath) / name
            other.add(path.stem)
            relpath = path.relative_to(root).as_posix()
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                m = re.search(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)", line)
                if m:
                    fns.setdefault(m.group(1), set()).add(relpath)
                m = MOD_ANY.match(line) or FIELD_DEF.match(line)
                if m:
                    other.add(m.group("name"))
    return fns, other


def audit_dead_names(root: Path) -> list[str]:
    """The backticked names in the Test cells of the audit's MUST and SHOULD rows that name
    nothing in the tree (see the module docstring for what counts as a name)."""
    fns, other = tree_names(root)
    errors = []
    for doc in sorted((root / "docs" / "conformance" / "audit").glob("*.md")):
        for n, line in enumerate(doc.read_text(encoding="utf-8").splitlines(), 1):
            if not line.startswith("| ") or line.startswith("| ID "):
                continue
            cells = [c.strip() for c in line.strip().strip("|").split(" | ")]
            if len(cells) < 8 or not AUDIT_LEVELS.match(cells[2].strip("`").upper()):
                continue
            for ref in backticked(cells[6]):
                ref = re.sub(r"\(.*$", "", ref.strip()).strip()
                file, _, name = ref.rpartition("::")
                if not AUDIT_NAME.fullmatch(name):
                    continue
                if name in fns:
                    base = re.split(r"[/\s]", file)[-1]
                    if base.endswith(".rs") and not any(p.rsplit("/", 1)[-1] == base for p in fns[name]):
                        errors.append(
                            f"{rel_to(doc, root)}:{n}: {cells[0]} cites `{ref}`: `{name}` is in"
                            f" {', '.join(sorted(fns[name]))}, not in {file}"
                        )
                    continue
                if name in other:
                    continue
                errors.append(f"{rel_to(doc, root)}:{n}: {cells[0]} cites `{ref}`, which names no fn in the tree")
    return errors


def rel_to(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def main() -> int:
    files = rust_files()
    findings: list[Finding] = []
    tests: dict[str, set[str]] = {}
    for path in files:
        scan_file(path, findings, tests)
    orphan_test_files(files, findings)
    feature_gated_findings(ROOT, findings)

    if "--list" in sys.argv:
        print("| Kind | File | Test | Reason | Covered by |")
        print("|---|---|---|---|---|")
        for f in sorted(findings, key=Finding.key):
            print(f"| {f.kind} | `{f.path}` | `{f.test}` | {f.detail} | |")
        return 0

    errors: list[str] = []

    # The exclusion table: Kind | File | Test | Reason | Covered by.
    excluded: dict[tuple[str, str, str], list[str]] = {}
    for cells in parse_table(EXCLUSIONS):
        if len(cells) < 5 or cells[0].lower() == "kind":
            continue
        key = (unquote(cells[0]), unquote(cells[1]), unquote(cells[2]))
        excluded[key] = cells
        if not cells[3].strip():
            errors.append(f"{EXCLUSIONS.name}: {key} has no reason")
        covered = cells[4].strip()
        if not covered:
            errors.append(f"{EXCLUSIONS.name}: {key} names no covering test")
        for ref in backticked(covered):
            if not test_exists(ref, tests):
                errors.append(f"{EXCLUSIONS.name}: {key} is covered by `{ref}`, which is not a test")

    found_keys = {f.key() for f in findings}
    for f in findings:
        if f.key() not in excluded:
            errors.append(f"{f.kind}: {f.path}: {f.test} ({f.detail}) is not in {EXCLUSIONS.name}")
    for key in excluded:
        if key not in found_keys:
            errors.append(f"{EXCLUSIONS.name}: {key} matches nothing any more; remove the row")

    # Conformance rows name the tests that prove a claim: each must exist.
    for doc in CONFORMANCE:
        if not doc.exists():
            continue
        rows = parse_table(doc)
        header = None
        for cells in rows:
            lowered = [c.lower() for c in cells]
            if "test" in lowered or "tests" in lowered:
                header = lowered
                continue
            if header is None:
                continue
            column = header.index("test") if "test" in header else header.index("tests")
            if column >= len(cells):
                continue
            for ref in backticked(cells[column]):
                if not test_exists(ref, tests):
                    errors.append(f"{rel(doc)}: the test `{ref}` does not exist")

    if "--check" in sys.argv:
        errors.extend(audit_dead_names(ROOT))

    if errors:
        print("Test inventory check failed:\n")
        for e in errors:
            print(f"  {e}")
        print(
            "\nEither make the test run (remove the #[ignore], restore it, add the `mod`, drop the"
            f" platform cfg) or list it in {rel(EXCLUSIONS)} with the reason and the test that"
            " covers the same behaviour."
        )
        return 1
    print(f"Test inventory: {sum(len(v) for v in tests.values())} tests, {len(findings)} excluded, all accounted for.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
