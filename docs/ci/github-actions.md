# Running VulnClaw headless in CI

VulnClaw's `run` command works unattended. Add `--non-interactive` and it issues
zero prompts, writes a machine-readable `summary.json` into the run directory,
and returns a distinct exit code so a pipeline can tell scan outcomes apart.

## The knobs

| flag | values | default | what it does |
|------|--------|---------|--------------|
| `--non-interactive` | (flag) | off | Headless: no prompts, structured output, exit-code contract. |
| `--scan-mode` | `quick` `standard` `deep` | `standard` | Depth preset over the effort knobs + fan-out cap. |
| `--scope-mode` | `auto` `full` | `full` | Recorded scope selection. `full` tests the whole surface (current behaviour); `auto` is consumed by the Target diff-scope model (#35) and falls back to `full` until that lands. |
| `--fail-on` | `verified` `any` `never` | `verified` | Which finding class trips a nonzero exit. |
| `--max-steps` / `--max-intents` / `--max-tool-rounds` / `--max-parallel` / `--max-rounds` | int | — | Override a single scan-mode dial. |

### Scan-mode presets

Presets seed from your `config.session` values, so `standard` mirrors whatever
you've tuned. `quick` shrinks effort and turns fan-out off (single agent);
`deep` deepens effort and opens the fan-out cap to its full width.

| mode | effort | fan-out |
|------|--------|---------|
| `quick` | shallow, fast | off (1 agent) |
| `standard` | moderate | light (`solve_max_parallel`) |
| `deep` | high rounds/steps | full (~12 concurrent) |

Explicit `--max-*` flags always override the preset.

## The exit-code contract

| code | meaning | CI |
|------|---------|-----|
| `0` | ran clean, nothing confirmed | pass |
| `1` | error — crash / bad config / missing LLM creds / bad target | fail (breakage) |
| `2` | ≥1 **verified** finding | blocks |
| `3` | only unverified candidates | warn |

A crashed or misconfigured scan exits `1`, never `0` — there is no silent green
CI on a broken scan.

`--fail-on` tunes which finding class trips a nonzero exit:

- `verified` (default): a verified finding exits `2`; unverified candidates do
  **not** block (exit `0`), so a PR gate isn't tripped by guesses.
- `any`: verified findings exit `2` and unverified candidates exit `3`.
- `never`: always exit `0` regardless of findings.

## Structured output

In `--non-interactive` mode a `summary.json` is written to
`~/.vulnclaw/runs/<target>-<timestamp>/` alongside the generated report. It
records the target, resolved scan profile, finding counts, and the exit code —
consume it in later pipeline steps.

## Prescribed workflows

Two ready-to-use workflows live next to this doc:

- **[`github-actions-pr-scan.yml`](./github-actions-pr-scan.yml)** — `on: pull_request`.
  Fast gate: `run --non-interactive --scan-mode quick --scope-mode auto --fail-on verified`.
  A verified finding (exit `2`) blocks the merge; candidates don't. (`--scope-mode
  auto` becomes a true diff-scoped gate once the Target diff-scope model, #35,
  lands; until then it scans full-surface.)
- **[`github-actions-scheduled-scan.yml`](./github-actions-scheduled-scan.yml)** — `on: schedule`.
  Deep full sweep: `run --non-interactive --scan-mode deep --scope-mode full --fail-on never`.
  Never breaks the pipeline; uploads the run directory and `findings.sarif` to
  code-scanning.

Both read LLM credentials from `VULNCLAW_LLM_API_KEY` / `VULNCLAW_LLM_BASE_URL` /
`VULNCLAW_LLM_MODEL` — provide them as Actions secrets.
