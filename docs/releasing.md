# Releasing

How a release of the workspace is published to crates.io and tagged. It is done by hand, by
someone who owns the crates on crates.io; `.github/workflows/release.yml` makes the GitHub
release from the tag and has the same publication list, commented out.

crates.io versions are permanent: a version that has been published can never be published
again or deleted. Yanking (`cargo yank`) is the only undo, and it only stops new lock files from
choosing the version. Read the whole procedure before starting.

## What is published

Nineteen crates, all at the workspace version. Dependencies come first: normal and build
dependencies, and dev-dependencies that carry a version (cargo keeps those in the published
manifest, so they must resolve on crates.io too).

1. `rtci-crypto`
2. `rtci-interceptor-derive`
3. `rtci-sframe`
4. `rtci-shared`
5. `rtci-dtls`
6. `rtci-mdns`
7. `rtci-rtcp`
8. `rtci-rtp`
9. `rtci-interceptor`
10. `rtci-media`
11. `rtci-sctp`
12. `rtci-datachannel`
13. `rtci-sdp`
14. `rtci-srtp`
15. `rtci-stun`
16. `rtci-ice`
17. `rtci-turn`
18. `rtci`
19. `rtci-stream-driver` (its default feature `peer` depends on `rtci`; the root crate's
    dev-dependency on it has no version, so `cargo publish` drops it)

The rename commit gives every crate its `rtci` name (`docs/rename.md`) and keeps this order.
`scripts/rename-to-rtci.py` prints it and writes it into release.yml.

Not published (`publish = false`): `rtci-signal` (the examples' signalling helper; the root
crate's dev-dependency on it has no version, so `cargo publish` drops it), the fuzz crates
(`fuzz/`, `rtci-*/fuzz/`), the benchmark (`benchmarks/aead-gcm`) and the test environment's
peers (`scripts/test-env/peers/`). The root crate's package holds the library sources, the README
and the licence texts only (`include` in `Cargo.toml`): the examples, integration tests,
fixtures and documentation stay in the repository.

The order is what `cargo metadata` gives (`python3 scripts/rename-to-rtci.py --dry-run`
prints it). When a crate gains or loses a dependency on another crate of the workspace,
regenerate the list and update this file and release.yml.

## The version on master between releases

After a release, `master` carries the next release's version with a `-dev` pre-release suffix
as soon as it takes its first change that the released line cannot take: after 0.1.0 and the
first breaking change, `0.2.0-dev` in `[workspace.package]` and in every
`[workspace.dependencies]` requirement on a workspace crate (and in the layers peer's
`Cargo.lock`). That says to git dependents that `master` is no longer 0.1-compatible, and it is
what lets the required "Check SemVer" job pass breaking changes: cargo-semver-checks reads
`0.1.0 -> 0.2.0-dev` as a new 0.x minor line, where they are allowed. The same job's report-only
step compares with the release type forced to minor and lists every breaking change since the
last release in the run's summary ("Breaking since v0.1.0"); each one listed must have an entry
in `CHANGELOG.md` under `### Breaking changes`. The release commit sets the plain version
(`0.2.0`), nothing else about the version changes then. A crates.io package is never made from
a `-dev` version.

## 0.1.0: order of operations

The first crates.io release is also the rename of every crate to its `rtci` name and the reset
of the version line to `0.1.0` (`docs/rename.md`, which arrives with the rename script). In
this order:

1. **Every release-gating branch is merged into `master`, and `master`'s CI is green** (cargo,
   fuzz, test environment, audit).
2. **The rename commit**: `python3 scripts/rename-to-rtci.py`, then `--check` exits 0,
   `cargo check --workspace --all-targets`, `cargo fmt --all --check` and every
   `scripts/check-*.py` gate pass; one commit, which is the release's last content commit. CI
   green on it.
3. **The release commit**: `CHANGELOG.md`'s `## [Unreleased]` becomes `## [0.1.0] - <date>`
   with a new empty `## [Unreleased]` above it; `SECURITY.md` names the 0.1 line (see "Before").
   The rename already set every version to `0.1.0`.
4. **The repository rename** to `Brainwires/rtci` on GitHub, before the tag: GitHub redirects
   the old URLs (git remotes, the REST API, web links, Actions), so CI and every clone keep
   working, and from then on the links the rename commit wrote resolve: the manifests'
   `repository` (each crate's crates.io page), `cliff.toml`'s repository (the release notes'
   commit and compare links), `SECURITY.md`'s advisory link, the README's issues link.
5. **The tag** `v0.1.0` on the release commit (see "Tag and release notes" for what it starts);
   its release page and notes are made under the new name.
6. **The dry runs** of "Dry runs" from a clean checkout of the tag, under the new names.
7. **Publish** in the order above, from a machine with a crates.io login (`cargo login` with a
   token that has `publish-new` and `publish-update`). Never from CI until publishing moves
   there; never with a token in the repository. A published version's metadata cannot be
   changed, so the repository must have its new name before this step.
8. **Detach from the fork network** (GitHub support request "detach fork"), so the repository
   stands on its own and its default pull request base is no longer upstream's.

A fix needed after step 5 (the tag) is a new commit and a patch release (`0.1.1`), never a moved tag.

## Before

1. The release commit is on `master` and its CI is green (cargo, fuzz, test environment).
2. `CHANGELOG.md`: the `## [Unreleased]` section becomes `## [X.Y.Z] - YYYY-MM-DD`, with a new
   empty `## [Unreleased]` above it. The version in `[workspace.package]` and in every
   `[workspace.dependencies]` requirement on a workspace crate is `X.Y.Z`.
3. `SECURITY.md`'s supported-versions table names the new line if it is a new minor version.
4. The draft-work register (`docs/conformance/draft-work.md`) is re-checked: for each entry,
   the W3C editor's draft and its `amendments.json`, the issues and PRs it names, the RFC errata
   and the datatracker; dates updated, and a default whose draft work has moved is changed (or
   the entry says why not) before the release commit (`docs/conformance/audit/RULES.md`,
   "Contradictions").
5. A crates.io API token with the `publish-new` and `publish-update` scopes, given to cargo
   with `cargo login` (it stays in `~/.cargo/credentials.toml`; never commit it or put it in
   the repository's secrets until publishing moves to CI).

## Tag and release notes

On the release commit, before publishing (the crates are then packaged from the tag):

```sh
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

The tag starts `.github/workflows/release.yml`: git-cliff (`cliff.toml`) writes the release
body from the conventional commits since the previous tag (breaking changes first, then one
section per kind, each capped with a link to `CHANGELOG.md`), and the GitHub release is
created. Read the generated release, and edit its text on GitHub where a summary of the
release's main changes at the top helps; `CHANGELOG.md` stays the full record.

For a patch release, correct the generated text by hand: git-cliff files every commit whose
type carries `!` (or a `BREAKING CHANGE` footer) under "Breaking changes", and the train's
behaviour-change commits use `!` too. A patch release has no breaking change (the SemVer Check
of its pull request says so), so move those entries under the release's behaviour changes
before the page is announced. 0.2.1's page needed it.

What a tag starts:

| Workflow | On a `v*` tag | What it does |
|---|---|---|
| `release.yml` | yes (`v[0-9]*.[0-9]*.[0-9]*`, so `v0.1.0`) | git-cliff release notes, then the GitHub release with them. Its crates.io publish step is commented out: it publishes nothing. |
| `cargo.yml`, `audit.yml`, `grcov.yml`, `semver.yml`, `test-env.yml`, `bench.yml`, `fuzz.yml`, `agent-test.yml` | no | Branch pushes, pull requests or dispatch only. |

No workflow builds or uploads binaries. `semver.yml` compares later changes with the latest
tag (`cargo semver-checks --baseline-rev`).

### History

The known issues on `v0.22.0+brainwires.6`'s release page were carried into 0.1.0: the
CHANGELOG's `[0.1.0]` summary lists the ones fixed since brainwires.6 and its "Known limits" the
ones still open, and the 0.1.0 release text carries the migration table of `docs/rename.md`
("For dependents"). Later releases take their open issues from the CHANGELOG's known limits.

## Dry runs

From a clean checkout of the release commit:

```sh
# What goes into each package, and nothing large or unintended
for p in rtci-crypto rtci-interceptor-derive rtci-sframe rtci-shared rtci-dtls rtci-mdns rtci-rtcp \
         rtci-rtp rtci-interceptor rtci-media rtci-sctp rtci-datachannel rtci-sdp rtci-srtp \
         rtci-stun rtci-ice rtci-turn rtci rtci-stream-driver; do
  cargo package --list -p "$p" > "/tmp/$p.files"
done

# Package and build every publishable crate. With several packages, cargo resolves the
# workspace's own not-yet-published crates from the packages it has just made, so this
# works before anything is on crates.io.
cargo publish --workspace --dry-run

# A crate whose workspace dependencies are already on crates.io (or that has none) can be
# checked on its own as well:
cargo publish --dry-run -p rtci-crypto

# Cargo.lock is gitignored, and the dry run does not leave one in the checkout on the current
# toolchain (0.2.1: none was written). Make it explicitly before the publish, from the same
# tree, so that a check of "the lock file is there and current" has something to read:
cargo generate-lockfile
```

`cargo publish -p <crate> --dry-run` on a crate whose workspace dependencies are not yet on
crates.io fails with "no matching package named ..." (or "failed to select a version"): that is
expected before the first publish and says nothing about the crate. The dry runs must otherwise
finish without errors; warnings about example and test targets "not included in the published
package" are the root crate's `include` at work.

The version is on the wire: the engine's default STUN SOFTWARE is `rtci-ice <version>`
(`rtci-ice/src/agent/mod.rs`, `DEFAULT_SOFTWARE`), so a version change changes the size of every
STUN packet and can move capacity figures. It did at the rename (train 18) and at
0.2.0: `rtci-ice 0.2.0-dev` (18 bytes, 20 padded) became `rtci-ice 0.2.0` (14 bytes, 16 padded),
which re-drew 2931 of the instrument's 3200 rows (capacity-compare run 45690259846; every
requirement met on both sides). The release pull request re-records
`tests/fixtures/capacity-instrument-baseline.tsv` on the bumped tree (ledger row `release-0.2.0`).
0.2.1: `rtci-ice 0.2.1` is as long as `rtci-ice 0.2.0` (14 bytes), so no STUN packet changes
size. The release pull request's instrument runs A, B and C are to give rows byte-identical to
those of the train-35 head 2495e62d (runs 45927526905, 45927534365, 45927538527), with no baseline
re-record and no ledger row.

## Publish

Either the whole workspace in one command, in dependency order, stopping at the first failure:

```sh
cargo publish --workspace
```

or one crate at a time, in the order above:

```sh
cargo publish -p rtci-crypto
cargo publish -p rtci-interceptor-derive
# ... every crate of the list, in order ...
cargo publish -p rtci
```

A script that checks the release commit before publishing (the 0.2.1 kit's checks that the
commit is the tag's, on `origin/master`'s first-parent line, with a clean tree and a current
lock file) must not test membership with `git rev-list --first-parent origin/master | grep -q
<sha>` under `set -o pipefail`: `grep -q` exits at the first match, `rev-list` is then killed by
SIGPIPE, and the pipeline fails although the commit is there. That refused the real v0.2.1
commit, master's tip. Take the list whole first, then search it:

```sh
fp=$(git rev-list --first-parent origin/master) || exit 1
grep -qx "$sha" <<<"$fp" || { echo "$sha is not on origin/master's first-parent line"; exit 1; }
```

`cargo publish` returns only once the crate is in the crates.io index (it waits up to
`publish.timeout`, 60 seconds by default), so the next crate resolves it. If it reports a
timeout while waiting, the crate is published: wait a minute and go on with the next one.
crates.io limits how fast new crate names can be published; a `429 Too Many Requests` answer
names when to retry. Wait that long and publish the same crate again (nothing was published).

## When a publish fails midway

Nothing is rolled back: the crates already published stay published.

- **The failing crate was not uploaded** (verification failed, a network error, a rate limit):
  fix the cause if there is one, commit it, and continue the list from that crate. The crates
  published before were packaged from the earlier commit; that is fine as long as the fix does
  not change them. If it does change one of them, that crate needs a new patch version
  (`X.Y.Z+1`) published after the fix.
- **A crate was published broken** (wrong contents, a missing feature, a bad dependency
  requirement): it cannot be replaced. Yank it (`cargo yank --version X.Y.Z -p <crate>`), fix
  the cause, raise that crate's version to the next patch, publish it, and carry on. Dependents
  with the requirement `X.Y` accept the patch release without a change. Note the yank in
  `CHANGELOG.md`.
- Never re-tag or move a tag to describe a different commit.

## After publishing

- **docs.rs**: every crate's build at `https://docs.rs/crate/<name>/<version>/builds` passed,
  with the features its `[package.metadata.docs.rs]` names. A failed build is retried from the
  docs.rs page once the cause is fixed in a new patch release.
- **Yanking**: a version published broken is yanked, `cargo yank --version <v> -p <name>`
  (undo: `--undo`), and replaced by a patch release; see "When a publish fails midway". A
  yank never deletes: existing lock files keep resolving it. Record it in `CHANGELOG.md`.
- **The rename, for dependents**: announce the `rtci` crates with the migration table of
  `docs/rename.md` ("For dependents": crate names and versions, `use` paths, feature
  references, `RUST_LOG` targets, or a `package =` rename on the dependent's side) in the
  GitHub release text and to the known dependents (ParolNet, the Denext binding). Their git
  dependencies on the old repository URL keep working through GitHub's redirect, but should
  move to the crates.io release.
- **The repository**: the rename and the detach of steps 4 and 8 are done; check that the
  README's links and `SECURITY.md` name the new repository.
