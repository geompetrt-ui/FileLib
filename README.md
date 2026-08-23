```
 _______ _____ _      _____ _      _____ ______
|__   __|_   _| |    |  ___| |    |_   _|  ___ \
   | |    | | | |    | |__ | |      | | | |__) )
   | |    | | | |    |  __|| |      | | |  __ /
   | |   _| |_| |____| |__ | |____ _| |_| |
   |_|  |_____|______|_____|______|_____|_|

     [ CLI file library // hacker edition ]
     root@filelib:~$ _
```

> A local file library with folders/subfolders: terminal CLI plus an
> optional web server in a hacker aesthetic (black background, green
> monospace text, matrix rain). No third-party dependencies — standard
> Python 3 library only.

---

## Table of contents

- [\[\*\] What filelib can do](#-what-filelib-can-do)
- [\[+\] Installation](#-installation)
  - [Linux / macOS](#linux--macos)
  - [Windows](#windows)
- [Quick start](#quick-start)
- [CLI command reference](#cli-command-reference)
- [Web interface](#web-interface)
- [Accounts and access control](#accounts-and-access-control)
- [Trash](#trash)
- [Environment variables](#environment-variables)
- [\[!\] Publishing via Tor (.onion)](#-publishing-via-tor-onion)
- [Security notes](#security-notes)

---

## [*] What filelib can do

**File organization**
- Files live in a tree of folders/subfolders, just like a normal
  filesystem (`work/reports/2026`, etc.)
- Add a file by copying or moving it (`--move`), with tags and a custom
  display name
- Search by name and tags, `tree` view, `ls` listing
- Move files and whole folders (`mv`), including drag & drop right in
  the browser
- Download any folder as a single ZIP archive

**Trash instead of irreversible deletion**
- Everything you delete (files and folders) moves to `.trash` and is
  kept there for a configurable number of days before being wiped for
  good
- Restore with one command/click, or purge everything manually at any
  time

**"Hacker edition" web server**
- A local HTTP server reachable from your phone and other devices on the
  same network
- Black background, green monospace text, matrix rain, scanlines — and
  underneath, a full-featured file manager: uploads (with a live progress
  bar), folder creation, search, and inline preview of text files and
  images in the browser
- Bulk operations: select several items with checkboxes → delete or move
  them all in one click
- Bilingual interface: English / Russian (switcher in the corner)

**Accounts and access control**
- Accounts (login/password) with granular permissions: `upload`,
  `mkdir`, `delete`, `security`, `admin`
- Without logging in, only viewing/downloading unprotected items is
  allowed — same as an anonymous guest
- A password can be set globally for the whole server (separately for
  "view", "download", "delete") **and** individually on a single file
- Fine-grained access grants: a specific account can be given access to
  a password-protected file without ever entering that password

**Zero dependencies**
- Runs on bare `python3` — nothing else to install

---

## [+] Installation

You only need **Python 3.8+**. Save the script as `filelib.py` (or
whatever name you like) — below are ways to get a `filelib` command
available from anywhere in your terminal.

### Linux / macOS

```bash
# 1. Put the script in your personal bin folder
mkdir -p ~/.local/bin
cp filelib.py ~/.local/bin/filelib
chmod +x ~/.local/bin/filelib

# 2. Make sure that folder is on your PATH
#    (if the line below isn't already there, add it to ~/.bashrc or ~/.zshrc)
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# 3. Verify
filelib
```

The script already has the shebang `#!/usr/bin/env python3`, so there's
no need to specify the interpreter separately — `filelib` runs like any
regular binary command.

Want it installed system-wide (for all users)? Same trick, but into
`/usr/local/bin`:

```bash
sudo cp filelib.py /usr/local/bin/filelib
sudo chmod +x /usr/local/bin/filelib
```

### Windows

1. Install Python from [python.org](https://www.python.org/downloads/windows/).
   On the first screen of the installer, **make sure to check**
   **"Add python.exe to PATH"**.

2. Create a folder for the tool, e.g. `C:\tools\filelib`, and put
   `filelib.py` there.

3. In the same folder, create a wrapper file called `filelib.bat` with
   the following content:

   ```bat
   @echo off
   python "%~dp0filelib.py" %*
   ```

4. Add `C:\tools\filelib` to your `PATH`:

   - **Via the GUI:** Settings → System → About → Advanced system
     settings → Environment Variables → add a new entry
     `C:\tools\filelib` to `Path` (user or system).
   - **Or via PowerShell** (run as your own user, admin rights not
     required):

     ```powershell
     [Environment]::SetEnvironmentVariable(
       "Path",
       $env:Path + ";C:\tools\filelib",
       "User"
     )
     ```

5. Open a **new** PowerShell or cmd window (environment variables are
   only picked up in new sessions) and check:

   ```powershell
   filelib
   ```

   If you have the `py` launcher instead of `python` on your PATH,
   change the line in `filelib.bat` to `py "%~dp0filelib.py" %*`.

---

## Quick start

```bash
filelib add ~/Documents/report.pdf --to work/reports --tag quarterly
filelib mkdir photos/2026/summer
filelib ls work/reports
filelib tree
filelib find report
filelib mv work/reports/report.pdf archive
filelib serve --port 8765
```

Your browser will open at `http://localhost:8765` (and the LAN address
is printed alongside it, for access from your phone).

---

## CLI command reference

| Command | What it does |
|---|---|
| `filelib add <file> [--to PATH] [--name NAME] [--tag TAG ...] [--move]` | add a file to the library (copy or move) |
| `filelib mkdir <path>` | create a folder, like `mkdir -p` |
| `filelib ls [path]` | list folder contents (non-recursive) |
| `filelib tree [path]` | show a folder/file tree |
| `filelib find <query>` | search by name and tags across the whole library |
| `filelib mv <source> <dest_folder>` | move a file or folder |
| `filelib info <path\|name\|id>` | show details about a file |
| `filelib open <path\|name\|id>` | open a file with the system app |
| `filelib rm <path\|name\|id> [-r] [-y]` | delete (moves to trash); `-r` for non-empty folders |
| `filelib trash ls` | show trash contents |
| `filelib trash restore <id\|name>` | restore from trash |
| `filelib trash empty [-y]` | permanently wipe the trash |
| `filelib user add <login> [-p PERMISSION ...] [--admin]` | create a web-interface account |
| `filelib user passwd <login>` | change an account's password |
| `filelib user grant/revoke <login> <permission>` | grant/revoke a permission |
| `filelib user rm <login> [-y]` | delete an account |
| `filelib user ls` | list accounts and their permissions |
| `filelib serve [--port 8765] [--host 0.0.0.0] [--no-browser]` | start the web server |

Files can be referenced in three ways: an exact library path
(`work/reports/report.pdf`), a name, or the start of an id — if the
match isn't unique, `filelib` lists the candidates and asks you to be
more specific.

---

## Web interface

`filelib serve` spins up a local site with the same hacker aesthetic:
matrix rain in the background, green terminal font, scanlines — and
underneath it, a full file manager:

- file uploads with a live progress bar (XHR, no page reload);
- folder creation right from the page;
- live search/filter by name;
- drag & drop — drag a file or folder row onto another folder to move
  it;
- checkbox selection and bulk delete/move for several items at once;
- download a whole folder as a single ZIP;
- inline preview of text files and images in a modal window, without
  downloading;
- EN/RU language switcher in the corner;
- `/api/files` — the same index as JSON (no password hashes) for your
  own scripts and automation.

---

## Accounts and access control

Accounts are created and managed **from the terminal**
(`filelib user ...`), or a visitor can self-register through the web
form — but self-registration grants no permissions, only viewing and
downloading whatever isn't password-protected.

Permissions you can grant:

| Permission | What it allows |
|---|---|
| `upload` | upload files via the web |
| `mkdir` | create folders via the web |
| `delete` | delete files/folders (to trash) |
| `security` | set/clear passwords on objects, grant fine-grained access |
| `admin` | all of the above + manage accounts via `/admin/users` |

Password protection works on two levels:

1. **Globally** — a separate password for "view", "download", and
   "delete" actions across the whole server (the "access control" panel,
   requires the `security` permission).
2. **Per file** — its own password on a single file; a specific account
   can be granted access to it without ever entering the password (the
   "grant" button next to the file).

---

## Trash

Anything deleted from the CLI (`rm`) or the web interface isn't wiped
immediately — it moves to `.trash` and is kept there for
`FILELIB_TRASH_DAYS` days (30 by default), then cleaned up
automatically. At any point you can:

```bash
filelib trash ls
filelib trash restore <id>
filelib trash empty
```

...or do the same from the `/trash` page in the web interface (requires
the `delete` permission).

---

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `FILELIB_HOME` | `~/.filelib` | where the index, files, and trash are stored |
| `FILELIB_TRASH_DAYS` | `30` | how many days to keep deleted items before wiping them |

---

## [!] Publishing via Tor (.onion)

If you want to reach your library from anywhere in the world without
forwarding ports on your router and without exposing your home IP, you
can run `filelib` as a **Tor hidden service (onion service)**. Anyone
with a regular **Tor Browser** can then open an address like
`abc123....onion`, with all traffic routed through the Tor network.

> Don't confuse two different tools: **Tor Browser** is the client used
> to *visit* sites, including `.onion` ones. To make your own server
> reachable as a `.onion` address, the machine running `filelib serve`
> needs the **`tor` daemon** installed and configured (same project, but
> the network service, not the browser) with hidden-service directives
> in its `torrc` config file.

### Step 1 — bind filelib to the local interface only

Since access will go through Tor, the server doesn't need to (and
shouldn't) listen on the whole internet directly:

```bash
filelib serve --host 127.0.0.1 --port 8765 --no-browser
```

### Step 2 — install the Tor daemon

**Linux (Debian/Ubuntu):**
```bash
sudo apt install tor
```
**Linux (Fedora):**
```bash
sudo dnf install tor
```
**Linux (Arch):**
```bash
sudo pacman -S tor
```
**macOS (Homebrew):**
```bash
brew install tor
```
**Windows:** download the **Tor Expert Bundle** from
[torproject.org — downloads](https://www.torproject.org/download/tor/)
(this is a separate package from Tor Browser — it includes `tor.exe`
and `torrc`, and it's the one that can run hidden services).

### Step 3 — add the hidden service to `torrc`

Locate the config file:
- Linux: `/etc/tor/torrc`
- macOS (brew): `/opt/homebrew/etc/tor/torrc` (or `/usr/local/etc/tor/torrc`)
- Windows: the `torrc` file next to `tor.exe` from the Expert Bundle
  (create it if it doesn't exist)

Add these two lines at the end:

```
HiddenServiceDir /var/lib/tor/filelib/
HiddenServicePort 80 127.0.0.1:8765
```

(on Windows, point `HiddenServiceDir` to a regular folder, e.g.
`C:\tor\hidden_filelib\`).

`HiddenServicePort 80 127.0.0.1:8765` means: from the outside the
service answers on "port 80" (a plain onion address with no port
needed), and internally it forwards to your local `filelib` on
`127.0.0.1:8765`.

### Step 4 — restart Tor and get your address

**Linux:**
```bash
sudo systemctl restart tor
sudo cat /var/lib/tor/filelib/hostname
```
**macOS:**
```bash
brew services restart tor
cat /opt/homebrew/var/lib/tor/filelib/hostname
```
**Windows** — run `tor.exe -f torrc` (e.g. from PowerShell in the Expert
Bundle folder), then open the `hostname` file inside the
`HiddenServiceDir` you specified.

The `hostname` file will contain something like:

```
abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion
```

That's your address — open it in **Tor Browser** on any device (just
download it from [torproject.org](https://www.torproject.org/); no
separate `tor` daemon is needed on the client side).

### Keeping it running

- **Linux:** run `filelib serve --host 127.0.0.1 --no-browser` via a
  `systemd` unit or inside `tmux`/`screen`, so the server doesn't die
  when you close the terminal; `tor` is already managed by the system
  service (`systemctl enable tor`).
- **Windows:** it's convenient to wrap `tor.exe` and `filelib serve` in
  Task Scheduler tasks set to run at logon, or use a third-party service
  wrapper (e.g. NSSM) to run them as proper Windows services.

---

## Security notes

- An onion address isn't a permanent secret — if it ends up in the wrong
  hands, whoever has it gets access. Before publishing your library over
  Tor, be sure to turn on global password protection (the "access
  control" panel, requires the `security` permission) and/or set up
  named accounts with `filelib user add`.
- Keep `filelib serve` on `--host 127.0.0.1` when access goes through
  Tor — all external traffic already goes through the hidden service,
  and binding to public `0.0.0.0` only widens the attack surface if the
  server is also reachable on a regular network at the same time.
- Trash isn't a backup: it protects against an accidental `rm`, not
  against disk failure. Keep a separate backup for anything important.
