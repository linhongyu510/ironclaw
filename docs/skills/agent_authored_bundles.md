# Agent-authored skill bundles: scripts, schemas, and references

How an agent creates and uses **multi-file** skills without changing how skills are
stored, discovered, or selected.

Raised by @henrypark133, whose objection was correct and is why this document exists.
The earlier proposal was "move skills to the filesystem" — an overhaul — and the
evidence did not support it. What the evidence supports is much narrower.

## What the measurements say

31-task SkillsBench/SkillLearnBench subset, `deepseek/deepseek-v4-flash`, reborn.
Two mechanisms, stratified by whether the skill ships files besides `SKILL.md`:

| skill type | n | prose injected | real files + listing | delta |
|---|---:|---:|---:|---:|
| ships resource files | 16 | 81.0% | **94.2%** | **+13.2pp**, 95% CI [+0.3, +26.2] |
| `SKILL.md` only | 11 | **91.5%** | 84.7% | **−6.9pp**, 95% CI [−20.4, +6.7] |

**The whole filesystem gain sits in skills that ship files. For prose-only skills,
injection is equal or better.** Filesystem-for-everything is therefore a regression on
13 of 31 tasks, paid to fix the other 18.

The ten largest per-task divergences make the same point without any averaging — the
four biggest filesystem wins all ship resources; the two biggest injection wins ship
none:

| task | inject | files | resource files |
|---|---:|---:|---:|
| citation_check | 0.000 | **0.833** | 13 |
| court_form_filling | 0.400 | **0.933** | 11 |
| lab_unit_harmonization | 0.479 | **1.000** | 1 |
| powerlifting_coef_calc | 0.700 | **0.950** | 6 |
| lake_warming | **1.000** | 0.250 | **0** |
| hvac_control | **1.000** | 0.929 | **0** |

Blending each stratum's measured winner (a projection, not a measured arm):

| strategy | blended (n=27) |
|---|---:|
| inject everything (today) | 85.3% |
| filesystem everything (the overhaul) | 90.3% |
| **files only when the skill ships resources** | **93.1%** |

### Why, mechanically

Nothing here is about models preferring filesystems.

1. **81 of the resources are executable** (`scripts/*.py`, `*.js`). A `SKILL.md` saying
   "run `scripts/extract_metadata.py`" is worse than useless when the file is absent:
   `citation_check` scored **0.000** that way, **0.833** once readable. You cannot
   execute pasted Python.
2. **Text resources are far too large to inline.** `exceltable_in_ppt` ships 986 KB of
   references and schemas — roughly **262,000 tokens** if folded into `SKILL.md`, per
   skill, per request. The 78 `.xsd` files are the full OOXML schema set; the agent needs
   the one element definition it is writing, not 1.9 MB.

Trace evidence: on `lab_unit_harmonization` the agent ran
`find / -path "*/lab-unit-harmonization*" -name "*.md"` — searching the real filesystem
for a file that existed only behind the virtual FS — and scored 0.458 where a harness
exposing the file scored 1.000. Its conversion factors live in
`reference/ckd_lab_features.md`, not `SKILL.md`.

**Small text resources should simply be inlined** (`lab_unit_harmonization` ships one
8 KB reference). A read path is only needed for executables and ooxml-scale bundles.

## Design: one extension, no storage change

### Storage, discovery and selection stay as they are

- `SkillBundleSource` is already a trait (`list_skill_bundles` + `read_bundle_file`) with
  several non-filesystem implementations in tree.
- Selection runs **per request**; there is no session-start index to migrate.
- `MountGrant("/skills" -> /tenants/{t}/users/{u}/skills, read_write_list_delete())`
  already exists (`factory.rs`), and discovery lists from
  `FilesystemSkillBundleRoot::user(ScopedPath("/skills"))` — **the same root**. Writes
  through that mount are visible to discovery with no plumbing.

### The extension

Grant it the existing `/skills` mount; expose three tools:

| tool | purpose |
|---|---|
| `skill_write_file(name, path, content)` | author any bundle file: `SKILL.md`, `scripts/*.py`, `schemas/*.xsd`, `references/*.md` |
| `skill_read_file(name, path)` | page one resource on demand (wraps `read_bundle_file`) |
| `skill_list_files(name)` | enumerate a bundle — see the gap below |

To **execute** a script the extension copies that single file into `/workspace`, which
the agent's filesystem already mounts, and the agent runs it with `shell`. No bulk
materialisation, no new mount for the agent.

`skill_install` is untouched and stays the path for prose skills. It takes one `content`
string capped at 64 KiB by `validate_lifecycle_text`, which is why it cannot express a
bundle. The extension writes through the mount instead of widening it — and must impose
its own per-file limit, since that route bypasses the cap.

### Gap this design must cover

`SkillBundleDescriptor` carries exactly one path — `skill_md_path`, hardcoded to
`SkillFilePath::skill_md()`. Discovery cannot advertise `scripts/` or `references/` at
all, so after the extension writes `scripts/extract.py` **nothing tells the agent it
exists** unless `SKILL.md` names it. That is the failure mode that scored
`citation_check` 0.000.

`skill_list_files` covers it from the extension with no core change. Adding a file list
to `SkillBundleDescriptor` avoids the round trip but touches core; prefer the extension
until the round trip is shown to matter.

## Scope

| component | change |
|---|---|
| new extension | the three tools above |
| capability grant | add the existing `/skills` MountGrant to the extension context |
| agent loop | register the tools |
| `ironclaw_skills` | `always_available` activation (in this PR; 2 files, opt-in) |
| skill storage / `SkillBundleSource` / selection | **unchanged** |
| `skill_install` | **unchanged** |
| prompt injection | **unchanged** — better for prose-only skills |

## Open decision: trust

`FilesystemSkillBundleRoot::user` marks bundles `SkillTrust::Trusted`. Granting an agent
write access there lets it author an **executable script into a trusted root** which
later runs. Small in code, significant in consequence. Agent-authored bundles likely
warrant a distinct trust level, and that call should be made before the write tool ships.
This is the real design question here, not the plumbing.

## Why `always_available` is needed regardless

Reborn scores a candidate skill only from `activation.keywords`/`tags`/`patterns` and
keeps it `if score > 0`; name and description contribute nothing. Measured on this
subset, **0 of 30 agent-authored skills contained an `activation` block** — a
self-authored skill could never be selected again, whatever its contents. Claude Code has
no such gate, and **0 of 30 claude-code-authored skills declare activation metadata**
either; several have no frontmatter at all. Without removing the gate, bundle quality is
unobservable.

## Validation status

- Ceiling (curated skills): reborn 90.4% vs claude-code 91.5%, paired **−0.8pp**,
  95% CI [−7.0, +5.3] — parity.
- Self-creation (user-simulator guided): reborn 90.1% vs claude-code 93.5%, paired
  **−2.7pp**, 95% CI [−9.0, +3.6], **14 of 20 tasks tied** — not distinguishable.
- The stratified numbers are n=16 and n=11 with wide intervals, and the resource-bearing
  lower bound is +0.3pp. The mechanism is trace-backed; the effect size is not tight.
  **Measure the extension as its own arm on the resource-bearing tasks before committing
  the trust work.**

## Explicitly unchanged: creation, discovery, indexing

To be unambiguous, since this is the crux of the objection — **none of the three is
migrated to the filesystem. All stay exactly as they are today.**

| concern | how it works today | after this design |
|---|---|---|
| **skill creation** | `skill_install` tool, one `content` string, 64 KiB cap (`commands.rs::parse_skill_install_command`) | **unchanged.** Still the path for prose skills. The extension adds `skill_write_file` alongside it for bundle files; `skill_install`'s parser is not touched. |
| **skill discovery** | `SkillBundleSource` trait — `list_skill_bundles` + `read_bundle_file`. Storage-agnostic; several non-filesystem impls in tree (`StaticSkillBundleSource`). Descriptors carry `skill_md_path`, `trust`, `visibility`, `provenance`, `description`. | **unchanged.** No new impl, no new trait method, no descriptor change. `skill_list_files` lives in the extension precisely so discovery does not have to change. |
| **indexing** | There is no session-start index. Selection runs **per request** (`select_activation_plan` / `activate_skills_for_run` take the current message). The only cache is a 5-minute in-memory TTL on catalog *search* results (`catalog.rs`). | **unchanged.** Nothing is pre-indexed today, so there is nothing to migrate. |
| **selection predicate** | `score_skill` over `activation.keywords`/`tags`/`patterns`, kept `if score > 0` | the one change, and it is opt-in: `always_available` (this PR). Needed because 0/30 agent-authored skills carry an `activation` block. |

The only filesystem interaction added anywhere is **runtime read** of a bundle file
through `read_bundle_file` (which already exists), plus copying a single script into
`/workspace` when the agent needs to execute it. Creation stays tool-based, discovery
stays trait-based, indexing stays absent.
