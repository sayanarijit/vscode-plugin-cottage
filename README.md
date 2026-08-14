# Cottage VS Code Extension

![The Cottage logo](media/cottage.png)

This extension installs [cottage](https://github.com/sayanarijit/cottage) with the best available package registry on the local machine, then configures a workspace so Copilot agent sessions do not keep decrypted secrets around or invoke `ctg` directly.

It also manages `.cott.age` files in the editor by decrypting them into their plaintext sibling when opened, then re-encrypting and cleaning up the plaintext file when you switch away or close it.

Repository: <http://github.com/sayanarijit/vscode-plugin-cottage>

It adds three commands:

- `Cottage: Install And Secure Workspace`
- `Cottage: Add Copilot Safety Hooks`
- `Cottage: Encrypt File`

## Installation

Install the extension from the Visual Studio Marketplace or locally from this repository.

### Option 1: Install from the Visual Studio Marketplace

Use this if you want the normal published extension.

1. Open the extension page: <https://marketplace.visualstudio.com/items?itemName=sayanarijit.vscode-plugin-cottage>
2. Click `Install`.
3. Open the workspace you want to secure.
4. Run one of the `Cottage:` commands from the Command Palette.

### Option 2: Run it as an unpacked development extension

Use this if you just want to try it immediately.

1. Clone the repository.
2. Open the cloned folder in VS Code.
3. Press `F5` to start an Extension Development Host.
4. In the new window, open the workspace you want to secure.
5. Run one of the `Cottage:` commands from the Command Palette.

### Option 3: Package a VSIX and install it

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

You can also right-click a file in the Explorer and choose `Cottage: Encrypt File`.

### Opening `.cott.age` files

`.cott.age` files are registered with a custom editor, so VS Code opens them through Cottage directly instead of showing the usual binary-file warning.

When you open `name.cott.age`, the extension runs `ctg decrypt name.cott.age`, opens `name` instead, and closes the encrypted tab.

When you switch away from the decrypted tab or close it, the extension saves it if needed, runs `ctg encrypt name --clean`, and closes the plaintext tab.

This behavior requires `ctg` to already be available on `PATH`.

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

### `Cottage: Encrypt File`

This Explorer file action encrypts the selected plaintext file with `ctg encrypt <file> --clean`.

Before encrypting, the extension:

1. Checks whether `ctg` is already available.
2. Installs `cottage` if needed, using the same installer detection order as `Cottage: Install And Secure Workspace`.
3. Looks for a `.cottage` setup in the selected file's workspace ancestry.
4. Runs `ctg init` in the workspace root when `.cottage` is missing.

If VS Code still cannot see the newly installed `ctg` binary, restart VS Code once and run the command again.

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
- Automatic `.cott.age` handling only works for files on the local filesystem.
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
