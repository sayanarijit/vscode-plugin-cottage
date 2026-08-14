# Cottage VS Code Extension

<p align="center">
	<picture>
		<source media="(prefers-color-scheme: dark)" srcset="media/cottage-dark.png">
		<img alt="The Cottage logo" width="320" src="media/cottage.png">
	</picture>
</p>

This extension installs [cottage](https://github.com/sayanarijit/cottage) with the best available package registry on the local machine, then configures a workspace so Copilot agent sessions do not keep decrypted secrets around or invoke `ctg` directly.

Repository: <http://github.com/sayanarijit/vscode-plugin-cottage>

It adds two commands:

- `Cottage: Install And Secure Workspace`
- `Cottage: Add Copilot Safety Hooks`

## Installation

This repository is currently set up as a source extension. Install it locally from the repo.

### Option 1: Run it as an unpacked development extension

Use this if you just want to try it immediately.

1. Clone the repository.
2. Open the cloned folder in VS Code.
3. Press `F5` to start an Extension Development Host.
4. In the new window, open the workspace you want to secure.
5. Run one of the `Cottage:` commands from the Command Palette.

### Option 2: Package a VSIX and install it

Use this if you want a normal locally installed extension.

1. Clone the repository.
2. Open a terminal in the repository root.
3. Package the extension:

```bash
npx @vscode/vsce package
```

4. In VS Code, run `Extensions: Install from VSIX...`.
5. Select the generated `.vsix` file.

## Usage

Open the target repository in VS Code, then run one of these commands from the Command Palette.

### `Cottage: Install And Secure Workspace`

This command does two things:

1. Checks whether `ctg` is already available on `PATH`.
2. If not, installs `cottage` using the first supported installer it finds.
3. Writes the workspace safety files.

Installer detection order:

1. `cargo binstall`
2. `cargo install`
3. `uv tool install`
4. `pipx install`
5. `python3 -m pip install --user`
6. `pnpm add -g`
7. `yarn global add`
8. `npm install -g`

If installation succeeds but `ctg` is still not visible to VS Code, restart VS Code once so the updated `PATH` is picked up.

### `Cottage: Add Copilot Safety Hooks`

This command only writes or updates the safety policy files. Use it when `ctg` is already installed and you only want the workspace protections.

## What the extension writes

The extension manages these files inside the target workspace:

- `.github/hooks/ctg-policy.json`
- `.github/hooks/scripts/deny_ctg_command.py`
- `.claude/settings.json`

The updates are idempotent. Running the commands again keeps the required cottage entries present without duplicating them.

## Safety model

The generated policy does four things:

1. Runs `ctg clean -qqq` at session start.
2. Runs `ctg clean -qqq` before each prompt submission.
3. Denies direct `ctg ...` shell commands from the agent through a pre-tool hook.
4. Adds a `Bash(ctg*)` deny rule in `.claude/settings.json`.

This reduces the chance that decrypted secret files remain on disk while an agent is working, and it prevents the agent from running direct `ctg` shell commands that could expose decrypted content.

## Typical workflow

1. Open a repository that already stores secrets with `cottage`, or plans to.
2. Run `Cottage: Install And Secure Workspace`.
3. Let the extension install `ctg` if needed.
4. Review the generated files in `.github/hooks/` and `.claude/`.
5. Start your Copilot agent session in that workspace.

## Notes

- The extension does not decrypt secrets for you.
- The extension does not modify your global shell profile.
- The extension expects the target workspace to be a repository where these policy files can be committed if you want the protections shared with the team.
- If your team already has custom `.claude/settings.json` or `.github/hooks/ctg-policy.json` content, the extension merges the required cottage entries instead of overwriting the whole file.

## Development

The repository is intentionally minimal. Basic validation is:

```bash
node --check src/extension.js
```

For manual testing:

1. Open this folder in VS Code.
2. Press `F5` to launch an Extension Development Host.
3. Run one of the `Cottage:` commands from the Command Palette.
