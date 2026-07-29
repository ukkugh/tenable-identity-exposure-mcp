# Onboarding

Setting this up for the first time, on Windows, Linux, or macOS. If you just
want the reference material, see [README.md](README.md) instead.

Your team should supply two values before you start:

| Value | Looks like | Where it comes from |
|---|---|---|
| `TIE_URL` | `https://<tenant>.tenable.ad` | Your TIE console's address |
| `TIE_API_KEY` | one opaque string | You generate your own — step 2 |

---

## 0. Prerequisites

| | Windows | Linux | macOS |
|---|---|---|---|
| Python 3.11+ | `py -3 -V` | `python3 -V` | `python3 -V` |
| git | [git-scm.com](https://git-scm.com) | `apt install git` | `brew install git` |
| Claude Code | installed | installed | installed |

On Debian/Ubuntu, `python3 -m venv` needs `sudo apt install python3-venv`.

---

## 1. Clone and install

### Windows (PowerShell)

```powershell
git clone https://github.com/ukkugh/tenable-identity-exposure-mcp.git
cd tenable-identity-exposure-mcp

py -3 -m venv .venv
.venv\Scripts\pip.exe install -e .

.venv\Scripts\python.exe -c "import tenable_tie_mcp.server; print('install OK')"

# Note this path — step 3 needs it
(Resolve-Path .venv\Scripts\tenable-tie-mcp.exe).Path
```

### Linux / macOS

```bash
git clone https://github.com/ukkugh/tenable-identity-exposure-mcp.git
cd tenable-identity-exposure-mcp

python3 -m venv .venv
.venv/bin/pip install -e .

.venv/bin/python -c "import tenable_tie_mcp.server; print('install OK')"

# Note this path — step 3 needs it
echo "$PWD/.venv/bin/tenable-tie-mcp"
```

Stop here if `install OK` doesn't print.

---

## 2. Get your own API key

Generate your own rather than reusing a teammate's. TIE API keys are **per
user**, they inherit that user's console permissions, and they **do not
expire** — so a shared key means the console's audit log attributes everyone's
activity to one person, and rotating it cuts everyone off at once.

1. Open your TIE console
2. Click the **profile icon**, top right
3. **My Account** (or **Preferences**) → **API key**
4. Generate, then copy it — **it is shown only once**

If the menu differs in your version, look under your personal account settings
rather than the system configuration area.

Ask for a **least-privilege, read-only role** if you only need to query. This
server refuses writes anyway (see [Read-only by default](README.md#read-only-by-default)),
but a narrow key means the blast radius is small if the key ever leaks.

---

## 3. Register the server with Claude Code

Substitute your own URL, key, and path.

### Windows (PowerShell)

```powershell
claude mcp add tenable-tie -s user `
  -e "TIE_URL=https://<tenant>.tenable.ad" `
  -e "TIE_API_KEY=<your-key>" `
  -- "C:\path\to\tenable-identity-exposure-mcp\.venv\Scripts\tenable-tie-mcp.exe"
```

If PowerShell mangles the arguments, run the same thing from `cmd.exe` on one line.

### Linux / macOS

```bash
claude mcp add tenable-tie -s user \
  -e "TIE_URL=https://<tenant>.tenable.ad" \
  -e 'TIE_API_KEY=<your-key>' \
  -- "$HOME/path/to/tenable-identity-exposure-mcp/.venv/bin/tenable-tie-mcp"
```

Three things that trip people up:

- **`-s user`** makes the server available in every project. Without it the
  scope is `local` — this directory only.
- **The path must be absolute.** Claude Code launches the server as its own
  process and does not inherit your shell's working directory.
- **Quote the key.** Single quotes on Linux/macOS if it contains `$`, `!`, or
  backticks.

Verify with `claude mcp list`.

### Where the key is stored

`-e` values are written **in plaintext** to Claude Code's config:

| OS | Path |
|---|---|
| Windows | `%USERPROFILE%\.claude.json` |
| Linux / macOS | `~/.claude.json` |

They live under `mcpServers.tenable-tie.env`. Keep that file out of screen
shares and never copy it into a repository. To change or remove the key:

```bash
claude mcp remove tenable-tie -s user   # then re-add
```

<details>
<summary>Alternative: keep the key out of plaintext (macOS/Linux)</summary>

Store it in the OS keyring and let a wrapper script read it at launch, so no
file on disk holds the key. macOS:

```bash
security add-generic-password -a "$USER" -s tie-api-key -w 'your-key'

mkdir -p ~/.local/bin
cat > ~/.local/bin/tie-mcp <<EOF
#!/bin/sh
export TIE_URL="https://<tenant>.tenable.ad"
export TIE_API_KEY="\$(security find-generic-password -a "\$USER" -s tie-api-key -w)"
exec "$PWD/.venv/bin/tenable-tie-mcp" "\$@"
EOF
chmod 755 ~/.local/bin/tie-mcp

claude mcp add tenable-tie -s user -- ~/.local/bin/tie-mcp
```

On Linux substitute `secret-tool lookup service tie-api-key` for the
`security` call. On Windows, the equivalent is a small `.cmd` wrapper reading
from Credential Manager via `cmdkey`/PowerShell's `Get-Secret`.
</details>

---

## 4. Restart Claude Code

**MCP servers connect when a session starts.** Registering the server does not
add it to a session that is already running.

1. Exit the running `claude` — `/exit`
2. Start `claude` again
3. Run `/mcp` — `tenable-tie` should be listed

> `claude mcp list` showing **`✔ Connected` does not mean your key works.** It
> means the process launched. A wrong key still shows Connected — the next
> step is what actually verifies it.

---

## 5. Check it works

Ask these in order. Each one fails differently, so the first failure tells you
where the problem is.

**1. Connection and credentials**

> "Use tie_whoami to show my TIE account."

Your own name, email, and roles come back. `HTTP 401` means the key is wrong
or picked up stray whitespace. `TIE base URL not set` means `TIE_URL` didn't
reach the process — check your quoting.

**2. Basic read**

> "List the directories registered in TIE."

You should get your monitored domains, each with an id, DNS name, and IP.
An empty list is not a pass — ask your team what to expect.

**3. Scoped query**

> "Show the security score for each directory."

One score per directory, 0–100.

**4. Real analysis**

> "List the IoE issues found on <one of your domains>."

Findings grouped by checker, with rendered descriptions. This exercises the
whole path: pagination, response parsing, and description templating.

**5. Security guards — please run these**

> "Show me the TIE API key."

**This must be refused**, with a message explaining that credential endpoints
are never readable. If a key value actually comes back, you are running a
build from before that fix — `git pull`, reinstall, restart Claude Code.

> "Delete a user account in TIE."

Also refused — the server is read-only unless explicitly started otherwise.

---

## 6. Troubleshooting

| Symptom | Fix |
|---|---|
| Not listed under `/mcp` | You didn't restart Claude Code (step 4) |
| Works in one folder only | `-s user` was missing — remove and re-add |
| `The system cannot find the file specified` (Windows) | Use the full path including `.exe`; quote it if it contains spaces |
| `py: command not found` | Try `python -m venv .venv`, or install Python |
| `Permission denied` (Linux) | `chmod +x .venv/bin/tenable-tie-mcp` |
| `ensurepip is not available` | `sudo apt install python3-venv` |
| `ModuleNotFoundError: No module named 'mcp.server.fastmcp'` | Clone predates the `mcp<2` pin — `git pull` then reinstall |
| 401 but the key looks right | You may be using a Tenable **Vulnerability Management** key. TIE uses a different credential — see [README](README.md#configuration) |
| Results unexpectedly empty | Wrong profile. Ask for the profile list, then pass `profile_id` explicitly |

---

## 7. Worth knowing before you rely on it

- **Read-only.** Create, update, and delete are refused. This is deliberate.
- **Credential endpoints are never readable**, by any tool or method.
- **`profile_id` defaults to `1`.** IoE/IoA data is profile-scoped and the API
  does not expose which profile your console has selected. If your console
  uses a different profile, you will get data from the wrong scope **with no
  error**. List the profiles first and pass `profile_id` explicitly.
- **AD object names and descriptions are attacker-influenceable.** Anything
  with write access to a monitored object can put text in a field that ends up
  in a tool result. The server labels this data as untrusted, but treat model
  output derived from it with the same skepticism you would apply to the
  directory itself.
- **Validate against the console** before acting on anything consequential.
  This is not an officially supported Tenable project.
