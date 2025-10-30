# Intro

This repository provides a proof of concept for automatically analysing
vulnerability scan outputs and preparing remediation pull requests with the help
of a small code-focused language model.

## MCP auto-remediation pipeline

The `mpc_owasp/` package contains the building blocks required to parse scan results,
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

The `Automated Remediation` workflow (`.github/workflows/auto-remediation.yml`)
triggers whenever the `Security Scan` workflow completes successfully and the
`AUTO_REMEDIATE` repository variable is set to `true`. It downloads the scan
artifact named `scan-results`, runs the MCP pipeline, and opens a remediation PR
if vulnerabilities are present.

### Required configuration

Set the following secrets and variables before enabling the workflow:

| Name | Type | Purpose |
| ---- | ---- | ------- |
| `AUTO_REMEDIATE` | repository variable | Opt-in switch for automated remediation. |
| `MCP_LLM_ENDPOINT` | secret | HTTPS endpoint for the small coding LLM (OpenAI-compatible). |
| `MCP_LLM_MODEL` | secret | Model identifier to request from the endpoint. |
| `MCP_LLM_API_KEY` | secret | API key or token for the LLM service. |
| `GITHUB_TOKEN` | secret | Token with `contents`/`pull_request` scopes (the default Actions token is sufficient). |

When the hosted secrets are absent the workflow automatically installs [Ollama](https://ollama.com/) inside the
GitHub Actions runner, launches a local inference server, and pulls the `qwen2.5-coder:3b` model. The local server
exposes an OpenAI-compatible API that the remediation pipeline uses to draft fixes and provide additional
recommendations inside the pull request body.

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

1. Copy the `mpc_owasp/` package and `scripts/auto_refactor.py` into the target
   repository (or install them as a package if published internally).
2. Add the required secrets/variables (`MCP_LLM_ENDPOINT`, `MCP_LLM_MODEL`,
   `MCP_LLM_API_KEY`, `AUTO_REMEDIATE`) and optionally `MCP_FORMATTER`/
   `MCP_MAX_VULNS` in the destination repository settings.
3. Drop the workflow from `.github/workflows/auto-remediation.yml` into the
   target repository and adjust the validation commands to reflect the
   project's test suite or formatters.
4. Ensure the vulnerability scanning workflow exports its findings as a
   `scan-results.json` artifact that follows the structure expected by
   `ScanParser`. See `ScanParser` docstrings for the minimal schema and extend
   the parser if your scanner requires custom handling.
5. Run the script locally using `--dry-run` on a sample scan file to confirm it
   understands the repository layout before enabling the GitHub Action.

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

Run the auto-refactor script locally with `--dry-run` to inspect generated
changes without touching remotes.

## Google Colab deployment with ngrok

When experimenting in Google Colab you can expose the local MCP server to the
internet with ngrok. Provide an ngrok auth token (either via the
`NGROK_AUTHTOKEN` environment variable or `--authtoken`) and run:

```bash
python scripts/deploy_colab_ngrok.py
```

The script installs the required Python packages, starts `mcp_server.py`, opens
an HTTPS tunnel, and prints the public endpoint you can share with other tools.
Use `--skip-install` if dependencies are already satisfied or `--skip-server` if
you plan to launch `mcp_server.py` yourself.
