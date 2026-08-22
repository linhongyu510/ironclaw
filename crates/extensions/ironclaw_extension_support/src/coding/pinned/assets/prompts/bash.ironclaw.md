Execute bash commands (`ls`, `grep`, `find`, `sed`, `awk`, `git`, build and test runners, …).

Pipelines, filters, redirection, `head`/`tail`, and multi-step `&&` chains are all first-class.

<instruction>
- Set `cwd` instead of `cd`; use `env: { NAME: "…" }` for multiline/quote-heavy values.
- Order-dependent commands use `&&` in one call; independent calls may run concurrently.
- Internal URIs (`skill://`, `agent://`, …) auto-resolve to paths.
- Output is captured. When it exceeds the inline window the last lines are kept, the full stream is at `artifact://<id>`, and the footer states the exact line range shown.
- Built-in `grep`/`glob`/`read` are also available and never truncate mid-file.
</instruction>
