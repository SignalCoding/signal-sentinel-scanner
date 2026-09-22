# Real-world skill fixture corpus - NOTICE

This directory is a regression corpus for the v3.0.1 skill-scanner false-positive
work (spec `_docs/ai/specs/v3.0.1-skill-false-positives.md`, item F14). It is test
data only; nothing here is shipped in the NuGet package or the Docker image.

## Third-party files (Apache License 2.0)

The following `SKILL.md` files are **verbatim, unmodified** copies taken from
Anthropic's public skills repository:

- Source: <https://github.com/anthropics/skills>
- Commit: `34040c9c568585f6929bedeaad110ad08f079624`
- Licence: Apache License, Version 2.0 (each skill directory in the upstream
  repository carries its own `LICENSE.txt` containing the full Apache-2.0 text;
  see also <http://www.apache.org/licenses/LICENSE-2.0>)
- Copyright: Anthropic, PBC

Files:

| File | Upstream path |
| ---- | ------------- |
| `academy-guide/SKILL.md`   | `skills/academy-guide/SKILL.md`   |
| `algorithmic-art/SKILL.md` | `skills/algorithmic-art/SKILL.md` |
| `claude-api/SKILL.md`      | `skills/claude-api/SKILL.md`      |
| `mcp-builder/SKILL.md`     | `skills/mcp-builder/SKILL.md`     |
| `skill-creator/SKILL.md`   | `skills/skill-creator/SKILL.md`   |

Only the `SKILL.md` file of each skill was copied. No other upstream file
(scripts, references, templates, assets) is reproduced here. The upstream
source-available skills (`docx`, `pdf`, `pptx`, `xlsx`) and any skill that is not
Apache-2.0 licensed are deliberately **not** included.

## Own-authored files

`office-helper/` and `coauthor/` are original files written by Signal Coding
Limited for this test corpus. They reproduce the *shape* of false positives
observed on proprietary third-party skills without copying any of their content:

- `office-helper/SKILL.md` + `office-helper/scripts/convert.py` - F3 (HTML inside a
  fenced block), F4 ("input file to output"), F7 ("Never share one ... object"),
  F11 (`[::-1]` with no execution sink), F12 (`/tmp/`), F13 (a fixed-literal
  `subprocess.run([...])` command).
- `coauthor/SKILL.md` - F1 (folded `>` block scalar description), F6
  ("transfer context, refine content through iteration") and, from the round-2
  "Gathering source material" section onwards, the .NET SDK 10.0.401 regex-engine
  regression (T1): that prose shape makes the source-generated engine return a
  bogus 337-character INJECTION-004 match that the interpreted engine rejects. The
  paragraph shape matters - do not reflow or reword it without re-checking
  `V301Round2RegressionTests.T1_*` and `RegexEngineIntegrityTests`.
