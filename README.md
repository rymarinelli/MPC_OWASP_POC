# Intro

This repository provides a proof of concept for automatically analysing
vulnerability scan outputs and preparing remediation pull requests with the help
of a small code-focused language model.

## MCP auto-remediation pipeline

The `mcp/` package contains the building blocks required to parse scan results,
craft prompts, invoke a language model, and write well-formatted patch
candidates back to the repository. Key components include:

* `ScanParser` – normalises JSON scan outputs into internal vulnerability
  records.
* `PromptBuilder` – assembles repository-aware prompts that instruct the model
  to return structured patch data.
* `PatchGenerator` – sends prompts to the configured language model endpoint,
  enforces formatting via pluggable formatters, and returns candidate patches.
* `AutoRemediationPipeline` – orchestrates the end-to-end flow and runs optional
  validation commands (tests, linters, format checks).

## Automated refactor script

The `scripts/auto_refactor.py` entrypoint connects the MCP components into a
complete workflow:

```bash
python scripts/auto_refactor.py \
  --scan-results path/to/scan-results.json \
  --validate "pytest" \
  --formatter "black {path}"
```

The script performs the following steps:

1. Parses the scan output and constructs remediation prompts.
2. Invokes the configured language model to obtain replacement file contents.
3. Applies patches to a temporary branch and runs the requested validation
   commands.
4. Commits the changes, pushes the branch, and opens a pull request summarising
   the detected issues.

Use `--dry-run` to skip the commit/push/PR phase when testing locally.

## GitHub Action integration

This repository now ships with a reusable composite action (`action.yml`) that
installs the MCP tooling and runs the auto-refactor pipeline inside any GitHub
Actions workflow. The bundled `Automated Remediation` workflow
(`.github/workflows/auto-remediation.yml`) consumes that action and triggers
whenever the `Security Scan` workflow completes successfully and the
`AUTO_REMEDIATE` repository variable is set to `true`. It downloads the scan
artifact named `scan-results`, runs the MCP pipeline, and opens a remediation PR
if vulnerabilities are present.

### Reusable action inputs

Reference the action from another workflow using the repository ref (e.g.
`uses: owner/mcp-owasp-poc@v1`). It accepts the following inputs:

| Input | Required | Description |
| ----- | -------- | ----------- |
| `scan_results` | ✅ | Path to the vulnerability scan JSON file relative to the workflow workspace. |
| `llm_endpoint` | ✅ | HTTPS endpoint for the OpenAI-compatible LLM. |
| `llm_model` | ✅ | Model identifier requested from the endpoint. |
| `llm_api_key` | ✅ | API key or token for the LLM service. |
| `github_token` | ❌ | Token with `contents`/`pull_request` scopes (defaults to the workflow token). |
| `github_repository` | ❌ | Repository in `owner/name` format (defaults to the current repository). |
| `repo_root` | ❌ | Path to the repository that should be remediated (defaults to the workflow workspace). |
| `base_branch` | ❌ | Branch used as the PR base. |
| `branch_prefix` | ❌ | Prefix applied to generated remediation branches. |
| `remote` | ❌ | Git remote to push remediation branches to (defaults to `origin`). |
| `formatter` | ❌ | Newline separated formatter command templates (e.g. `black {path}`). |
| `validations` | ❌ | Newline separated validation commands (e.g. `pytest`). |
| `max_vulnerabilities` | ❌ | Upper bound on the number of findings to remediate. |
| `dry_run` | ❌ | Set to `true` to skip committing, pushing, and PR creation. |
| `python_version` | ❌ | Python runtime to install (defaults to `3.11`). |

Example usage within a workflow:

```yaml
- name: Run MCP auto-remediation
  uses: owner/mcp-owasp-poc@v1
  with:
    scan_results: artifacts/scan-results.json
    llm_endpoint: ${{ secrets.MCP_LLM_ENDPOINT }}
    llm_model: ${{ secrets.MCP_LLM_MODEL }}
    llm_api_key: ${{ secrets.MCP_LLM_API_KEY }}
    github_token: ${{ secrets.GITHUB_TOKEN }}
    formatter: |
      black {path}
    validations: |
      pytest
```

Ensure the workflow checks out the target repository and installs any
project-specific dependencies before invoking the action so validation commands
have the required tooling available.

### Required configuration

Set the following secrets and variables before enabling the workflow:

| Name | Type | Purpose |
| ---- | ---- | ------- |
| `AUTO_REMEDIATE` | repository variable | Opt-in switch for automated remediation. |
| `MCP_LLM_ENDPOINT` | secret | HTTPS endpoint for the small coding LLM (OpenAI-compatible). |
| `MCP_LLM_MODEL` | secret | Model identifier to request from the endpoint. |
| `MCP_LLM_API_KEY` | secret | API key or token for the LLM service. |
| `GITHUB_TOKEN` | secret | Token with `contents`/`pull_request` scopes (the default Actions token is sufficient). |

Optional repository variables can provide additional guardrails:

* `MCP_FORMATTER` – default formatter template (e.g. `black {path}`) if not
  supplied on the command line.
* `MCP_MAX_VULNS` – limit of findings to remediate per run.

### Safety checks

* Validation commands (e.g. `pytest`, formatters) run before any commit is
  produced to ensure generated patches comply with project standards.
* The generated pull request body enumerates every vulnerability and its
  severity to support auditing.
* Branches are created uniquely per run (`auto/remediate-<timestamp>`) to avoid
  collisions with manual work.

## Using the pipeline in other repositories

The MCP tooling is designed to be portable across projects. To enable automated
remediation in another repository:

1. Reference the composite action from a workflow (for example,
   `uses: owner/mcp-owasp-poc@v1`) or install the package and run the
   `mcp-auto-refactor` console script directly.
2. Add the required secrets/variables (`MCP_LLM_ENDPOINT`, `MCP_LLM_MODEL`,
   `MCP_LLM_API_KEY`, `AUTO_REMEDIATE`) and optionally `MCP_FORMATTER`/
   `MCP_MAX_VULNS` in the destination repository settings.
3. Ensure the vulnerability scanning workflow exports its findings as a
   `scan-results.json` artifact that follows the structure expected by
   `ScanParser`. See `ScanParser` docstrings for the minimal schema and extend
   the parser if your scanner requires custom handling.
4. Run the script or action locally using `--dry-run` on a sample scan file to
   confirm it understands the repository layout before enabling automated PRs.

### Integrating Semgrep OWASP Top 10 checks

The repository ships with `semgrep/owasp-top10.yml`, a rule pack that targets
common Python weaknesses mapped to the OWASP Top 10. To incorporate the rules
into an existing security scan workflow:

```bash
semgrep --config semgrep/owasp-top10.yml --json --output scan-results.json
```

Feed the generated JSON into the MCP pipeline or merge it with other scanner
outputs before invoking `scripts/auto_refactor.py`.

## Development setup

Install dependencies with:

```bash
pip install -r requirements.txt
```

### Installing as a package

The project includes a `pyproject.toml`, allowing it to be installed as a
standard Python package. This makes it easier to distribute the MCP tooling to
other repositories without copying the source tree.

```bash
pip install .
```

Once installed, the `mcp-auto-refactor` console script becomes available. It is
functionally equivalent to running `python scripts/auto_refactor.py` and can be
invoked from any repository:

```bash
mcp-auto-refactor --scan-results path/to/scan-results.json --dry-run
```

Run the auto-refactor script locally with `--dry-run` to inspect generated
changes without touching remotes.
