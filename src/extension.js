const vscode = require('vscode');
const fs = require('fs/promises');
const path = require('path');
const os = require('os');
const { spawn } = require('child_process');

const CLEAN_COMMAND = 'ctg clean -qqq';
const DENY_SCRIPT_RELATIVE_PATH = path.join('.github', 'hooks', 'scripts', 'deny_ctg_command.py');
const CTG_POLICY_RELATIVE_PATH = path.join('.github', 'hooks', 'ctg-policy.json');
const CLAUDE_SETTINGS_RELATIVE_PATH = path.join('.claude', 'settings.json');
const ENCRYPTED_FILE_SUFFIX = '.cott.age';

const trackedFiles = new Map();
const decryptInFlight = new Set();
let activeTrackedDocumentPath = null;

const DENY_SCRIPT_CONTENT = `#!/usr/bin/env python3

import json
import re
import sys


TERMINAL_TOOL_NAMES = {
    "bash",
    "run_in_terminal",
    "runinterminal",
    "terminal",
    "shell",
}


def _normalize_tool_name(value):
    return re.sub(r"[^a-z]", "", str(value or "").lower())


def _extract_command(tool_input):
    if not isinstance(tool_input, dict):
        return ""

    for key in ("command", "cmd", "text"):
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    args = tool_input.get("args")
    if isinstance(args, list):
        parts = [part for part in args if isinstance(part, str) and part.strip()]
        if parts:
            return " ".join(parts)

    return ""


def main():
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0

    tool_name = _normalize_tool_name(payload.get("tool_name"))
    if tool_name not in TERMINAL_TOOL_NAMES:
        return 0

    command = _extract_command(payload.get("tool_input"))
    if not re.match(r"^ctg(?:\\s|$)", command):
        return 0

    json.dump(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "Direct ctg shell commands are blocked by workspace policy; rely on the session hooks instead.",
                "additionalContext": "A workspace hook already runs 'ctg clean -qqq' at session start and on every prompt submission."
            }
        },
        sys.stdout,
    )
    sys.stdout.write("\\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
`;

function activate(context) {
  context.subscriptions.push(
    vscode.commands.registerCommand('cottage.installAndSecureWorkspace', async (uri) => {
      await runInstallAndSecure(uri);
    }),
    vscode.commands.registerCommand('cottage.secureWorkspace', async (uri) => {
      await runSecureWorkspace(uri);
    }),
    vscode.workspace.onDidOpenTextDocument((document) => {
      void handleDocumentOpened(document);
    }),
    vscode.workspace.onDidCloseTextDocument((document) => {
      void handleDocumentClosed(document);
    }),
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      void handleActiveEditorChanged(editor);
    })
  );

  void initializeEncryptedDocumentHandling();
}

function deactivate() {}

async function initializeEncryptedDocumentHandling() {
  for (const document of vscode.workspace.textDocuments) {
    await handleDocumentOpened(document);
  }

  await handleActiveEditorChanged(vscode.window.activeTextEditor);
}

async function handleDocumentOpened(document) {
  if (!isEncryptedDocument(document)) {
    return;
  }

  await decryptAndRevealDocument(document.uri);
}

async function handleDocumentClosed(document) {
  const trackedDocument = trackedFiles.get(normalizeTrackedPath(document.uri.fsPath));
  if (!trackedDocument) {
    return;
  }

  await finalizeTrackedDocument(trackedDocument.decryptedPath);
}

async function handleActiveEditorChanged(editor) {
  const nextTrackedPath = editor ? getTrackedDocumentPath(editor.document) : null;
  const previousTrackedPath = activeTrackedDocumentPath;

  activeTrackedDocumentPath = nextTrackedPath;

  if (previousTrackedPath && previousTrackedPath !== nextTrackedPath) {
    await finalizeTrackedDocument(previousTrackedPath);
  }
}

async function decryptAndRevealDocument(uri) {
  const encryptedPath = uri.fsPath;
  const decryptedPath = getDecryptedPath(encryptedPath);

  if (!decryptedPath) {
    return;
  }

  const decryptKey = normalizeTrackedPath(encryptedPath);
  if (decryptInFlight.has(decryptKey)) {
    return;
  }

  decryptInFlight.add(decryptKey);

  try {
    await runCommand('ctg', ['decrypt', encryptedPath], path.dirname(encryptedPath));

    const trackedDocument = trackedFiles.get(normalizeTrackedPath(decryptedPath)) || {
      decryptedPath,
      encryptedPath,
      encryptPromise: null,
      finalizing: false,
    };

    trackedDocument.encryptedPath = encryptedPath;
    trackedDocument.finalizing = false;
    trackedFiles.set(normalizeTrackedPath(decryptedPath), trackedDocument);

    const document = await vscode.workspace.openTextDocument(decryptedPath);
    await vscode.window.showTextDocument(document, {
      preview: false,
      preserveFocus: false,
    });

    await closeTabsForUri(uri);
  } catch (error) {
    vscode.window.showErrorMessage(formatError(error));
  } finally {
    decryptInFlight.delete(decryptKey);
  }
}

async function finalizeTrackedDocument(decryptedPath) {
  const trackedKey = normalizeTrackedPath(decryptedPath);
  const trackedDocument = trackedFiles.get(trackedKey);
  if (!trackedDocument) {
    return;
  }

  if (trackedDocument.encryptPromise) {
    try {
      await trackedDocument.encryptPromise;
    } catch {
      // The original finalize call already surfaced the error.
    }
    return;
  }

  trackedDocument.finalizing = true;
  trackedDocument.encryptPromise = (async () => {
    try {
      const document = findOpenDocument(trackedDocument.decryptedPath);
      if (document && document.isDirty) {
        const saved = await document.save();
        if (!saved || document.isDirty) {
          throw new Error(`Failed to save ${path.basename(trackedDocument.decryptedPath)} before encryption.`);
        }
      }

      await runCommand(
        'ctg',
        ['encrypt', trackedDocument.decryptedPath, '--clean'],
        path.dirname(trackedDocument.decryptedPath)
      );

      await closeTabsForUri(vscode.Uri.file(trackedDocument.decryptedPath));
    } catch (error) {
      trackedDocument.finalizing = false;
      trackedDocument.encryptPromise = null;
      throw error;
    }

    trackedFiles.delete(trackedKey);
    if (activeTrackedDocumentPath === trackedDocument.decryptedPath) {
      activeTrackedDocumentPath = null;
    }
  })();

  try {
    await trackedDocument.encryptPromise;
  } catch (error) {
    vscode.window.showErrorMessage(formatError(error));
  }
}

async function runInstallAndSecure(uri) {
  const folder = await pickWorkspaceFolder(uri);
  if (!folder) {
    return;
  }

  try {
    const result = await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: 'Cottage',
        cancellable: false,
      },
      async (progress) => {
        progress.report({ message: 'Checking for an existing ctg installation' });
        let installSummary = 'ctg is already available on PATH.';

        const existingCtg = await findExecutable('ctg');
        if (!existingCtg) {
          progress.report({ message: 'Detecting the best installer for this environment' });
          const candidate = await detectBestInstaller();
          if (!candidate) {
            throw new Error(
              'No supported installer was found. Expected one of: cargo, uv, pipx, python3, pnpm, yarn, or npm.'
            );
          }

          progress.report({ message: `Installing cottage via ${candidate.label}` });
          await runCommand(candidate.command, candidate.args, folder.uri.fsPath);
          installSummary = `Installed cottage via ${candidate.label}.`;

          if (!(await findExecutable('ctg'))) {
            installSummary += ' Restart VS Code if hooks cannot find ctg on PATH yet.';
          }
        }

        progress.report({ message: 'Writing Copilot and workspace safety policy files' });
        const writeSummary = await secureWorkspace(folder.uri.fsPath);

        return {
          installSummary,
          writeSummary,
        };
      }
    );

    const message = `${result.installSummary} ${result.writeSummary}`;
    const action = await vscode.window.showInformationMessage(
      message,
      'Open policy file',
      'Open settings file'
    );

    if (action === 'Open policy file') {
      await openFile(path.join(folder.uri.fsPath, CTG_POLICY_RELATIVE_PATH));
    }

    if (action === 'Open settings file') {
      await openFile(path.join(folder.uri.fsPath, CLAUDE_SETTINGS_RELATIVE_PATH));
    }
  } catch (error) {
    vscode.window.showErrorMessage(formatError(error));
  }
}

async function runSecureWorkspace(uri) {
  const folder = await pickWorkspaceFolder(uri);
  if (!folder) {
    return;
  }

  try {
    const summary = await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: 'Cottage',
        cancellable: false,
      },
      async (progress) => {
        progress.report({ message: 'Writing Copilot and workspace safety policy files' });
        return secureWorkspace(folder.uri.fsPath);
      }
    );

    vscode.window.showInformationMessage(summary);
  } catch (error) {
    vscode.window.showErrorMessage(formatError(error));
  }
}

async function secureWorkspace(workspaceRoot) {
  const policyPath = path.join(workspaceRoot, CTG_POLICY_RELATIVE_PATH);
  const denyScriptPath = path.join(workspaceRoot, DENY_SCRIPT_RELATIVE_PATH);
  const claudeSettingsPath = path.join(workspaceRoot, CLAUDE_SETTINGS_RELATIVE_PATH);

  await fs.mkdir(path.dirname(policyPath), { recursive: true });
  await fs.mkdir(path.dirname(denyScriptPath), { recursive: true });
  await fs.mkdir(path.dirname(claudeSettingsPath), { recursive: true });

  const policyChange = await mergeJsonFile(policyPath, mergeCopilotPolicy);
  const settingsChange = await mergeJsonFile(claudeSettingsPath, mergeClaudeSettings);
  const denyScriptChange = await writeTextFile(denyScriptPath, DENY_SCRIPT_CONTENT, 0o755);

  const changes = [policyChange, settingsChange, denyScriptChange].filter((change) => change.changed).length;
  if (changes === 0) {
    return 'Workspace safety files were already up to date.';
  }

  return `Updated ${changes} workspace safety file${changes === 1 ? '' : 's'}.`;
}

function mergeCopilotPolicy(existing) {
  const root = asObject(existing);
  const hooks = asObject(root.hooks);

  hooks.SessionStart = ensureHookCommand(
    hooks.SessionStart,
    {
      type: 'command',
      command: CLEAN_COMMAND,
      timeout: 30,
    },
    ['type', 'command']
  );
  hooks.UserPromptSubmit = ensureHookCommand(
    hooks.UserPromptSubmit,
    {
      type: 'command',
      command: CLEAN_COMMAND,
      timeout: 30,
    },
    ['type', 'command']
  );
  hooks.PreToolUse = ensureHookCommand(
    hooks.PreToolUse,
    {
      type: 'command',
      command: 'python3 .github/hooks/scripts/deny_ctg_command.py',
      timeout: 15,
    },
    ['type', 'command']
  );

  return {
    ...root,
    hooks,
  };
}

function mergeClaudeSettings(existing) {
  const root = asObject(existing);
  const permissions = asObject(root.permissions);
  const deny = Array.isArray(permissions.deny) ? permissions.deny.filter((item) => typeof item === 'string') : [];

  if (!deny.includes('Bash(ctg*)')) {
    deny.push('Bash(ctg*)');
  }

  return {
    ...root,
    permissions: {
      ...permissions,
      deny,
    },
  };
}

function ensureHookCommand(existingValue, desiredEntry, identityKeys) {
  const entries = Array.isArray(existingValue) ? existingValue.filter(isPlainObject) : [];
  const desiredIdentity = JSON.stringify(identityKeys.map((key) => desiredEntry[key] ?? null));
  const remaining = entries.filter((entry) => {
    const entryIdentity = JSON.stringify(identityKeys.map((key) => entry[key] ?? null));
    return entryIdentity !== desiredIdentity;
  });

  remaining.push(desiredEntry);
  return remaining;
}

async function mergeJsonFile(filePath, mergeFn) {
  let existing = {};
  let hadExistingFile = false;

  try {
    const raw = await fs.readFile(filePath, 'utf8');
    existing = JSON.parse(raw);
    hadExistingFile = true;
  } catch (error) {
    if (error && error.code !== 'ENOENT') {
      throw new Error(`Failed to read ${path.basename(filePath)}: ${error.message}`);
    }
  }

  const nextValue = mergeFn(existing);
  const nextContent = `${JSON.stringify(nextValue, null, 2)}${os.EOL}`;

  if (hadExistingFile) {
    const currentContent = await fs.readFile(filePath, 'utf8');
    if (currentContent === nextContent) {
      return { changed: false };
    }
  }

  await fs.writeFile(filePath, nextContent, 'utf8');
  return { changed: true };
}

async function writeTextFile(filePath, content, mode) {
  let currentContent = null;

  try {
    currentContent = await fs.readFile(filePath, 'utf8');
  } catch (error) {
    if (error && error.code !== 'ENOENT') {
      throw new Error(`Failed to read ${path.basename(filePath)}: ${error.message}`);
    }
  }

  if (currentContent === content) {
    return { changed: false };
  }

  await fs.writeFile(filePath, content, 'utf8');
  if (typeof mode === 'number') {
    await fs.chmod(filePath, mode);
  }
  return { changed: true };
}

async function pickWorkspaceFolder(uri) {
  if (uri && uri.fsPath) {
    const directMatch = vscode.workspace.getWorkspaceFolder(uri);
    if (directMatch) {
      return directMatch;
    }
  }

  const folders = vscode.workspace.workspaceFolders || [];
  if (folders.length === 0) {
    vscode.window.showErrorMessage('Open a workspace folder before configuring cottage.');
    return null;
  }

  if (folders.length === 1) {
    return folders[0];
  }

  const picked = await vscode.window.showWorkspaceFolderPick({
    placeHolder: 'Select the workspace to secure with cottage',
  });

  return picked || null;
}

async function detectBestInstaller() {
  const candidates = [
    {
      label: 'cargo binstall (crates.io binary)',
      command: 'cargo',
      args: ['binstall', '--locked', 'cottage', '-y'],
      available: async () => {
        if (!(await findExecutable('cargo'))) {
          return false;
        }

        return commandSucceeds('cargo', ['binstall', '--help']);
      },
    },
    {
      label: 'cargo install (crates.io source)',
      command: 'cargo',
      args: ['install', '--locked', 'cottage'],
      available: async () => Boolean(await findExecutable('cargo')),
    },
    {
      label: 'uv tool install (PyPI)',
      command: 'uv',
      args: ['tool', 'install', '--force', 'cottage'],
      available: async () => Boolean(await findExecutable('uv')),
    },
    {
      label: 'pipx install (PyPI)',
      command: 'pipx',
      args: ['install', '--force', 'cottage'],
      available: async () => {
        if (!(await findExecutable('pipx'))) {
          return false;
        }

        return commandSucceeds('pipx', ['--version']);
      },
    },
    {
      label: 'python3 -m pip (PyPI user install)',
      command: 'python3',
      args: ['-m', 'pip', 'install', '--user', 'cottage'],
      available: async () => {
        if (!(await findExecutable('python3'))) {
          return false;
        }

        return commandSucceeds('python3', ['-m', 'pip', '--version']);
      },
    },
    {
      label: 'pnpm global add (npm registry)',
      command: 'pnpm',
      args: ['add', '-g', '@sayanarijit/cottage'],
      available: async () => Boolean(await findExecutable('pnpm')),
    },
    {
      label: 'yarn global add (npm registry)',
      command: 'yarn',
      args: ['global', 'add', '@sayanarijit/cottage'],
      available: async () => Boolean(await findExecutable('yarn')),
    },
    {
      label: 'npm global install (npm registry)',
      command: 'npm',
      args: ['install', '-g', '@sayanarijit/cottage'],
      available: async () => Boolean(await findExecutable('npm')),
    },
  ];

  for (const candidate of candidates) {
    if (await candidate.available()) {
      return candidate;
    }
  }

  return null;
}

async function runCommand(command, args, cwd) {
  const executablePath = await findExecutable(command);
  if (!executablePath) {
    throw new Error(`Unable to find executable: ${command}`);
  }

  await new Promise((resolve, reject) => {
    const child = spawn(executablePath, args, {
      cwd,
      env: process.env,
      shell: false,
    });

    let stderr = '';

    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
    });

    child.on('error', (error) => {
      reject(error);
    });

    child.on('close', (code) => {
      if (code === 0) {
        resolve();
        return;
      }

      reject(new Error(stderr.trim() || `${command} exited with code ${code}`));
    });
  });
}

async function commandSucceeds(command, args) {
  try {
    await runCommand(command, args, process.cwd());
    return true;
  } catch {
    return false;
  }
}

async function findExecutable(command) {
  const envPath = process.env.PATH || '';
  const pathParts = envPath.split(path.delimiter).filter(Boolean);
  const executableNames = getExecutableNames(command);

  for (const directory of pathParts) {
    for (const executableName of executableNames) {
      const candidatePath = path.join(directory, executableName);
      try {
        await fs.access(candidatePath);
        return candidatePath;
      } catch {
        continue;
      }
    }
  }

  return null;
}

function getExecutableNames(command) {
  if (process.platform !== 'win32') {
    return [command];
  }

  const extensions = (process.env.PATHEXT || '.EXE;.CMD;.BAT;.COM')
    .split(';')
    .filter(Boolean)
    .map((extension) => extension.toLowerCase());

  return [command, ...extensions.map((extension) => `${command}${extension}`)];
}

function asObject(value) {
  return isPlainObject(value) ? { ...value } : {};
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function isEncryptedDocument(document) {
  return document.uri.scheme === 'file' && document.fileName.endsWith(ENCRYPTED_FILE_SUFFIX);
}

function getDecryptedPath(encryptedPath) {
  if (!encryptedPath.endsWith(ENCRYPTED_FILE_SUFFIX)) {
    return null;
  }

  return encryptedPath.slice(0, -ENCRYPTED_FILE_SUFFIX.length);
}

function getTrackedDocumentPath(document) {
  if (!document || document.uri.scheme !== 'file') {
    return null;
  }

  const trackedDocument = trackedFiles.get(normalizeTrackedPath(document.uri.fsPath));
  return trackedDocument ? trackedDocument.decryptedPath : null;
}

function normalizeTrackedPath(filePath) {
  return process.platform === 'win32' ? filePath.toLowerCase() : filePath;
}

function findOpenDocument(filePath) {
  return vscode.workspace.textDocuments.find(
    (document) => document.uri.scheme === 'file' && normalizeTrackedPath(document.uri.fsPath) === normalizeTrackedPath(filePath)
  );
}

async function closeTabsForUri(uri) {
  const tabs = [];

  for (const group of vscode.window.tabGroups.all) {
    for (const tab of group.tabs) {
      if (isUriBackedTab(tab.input) && tab.input.uri.fsPath === uri.fsPath) {
        tabs.push(tab);
      }
    }
  }

  if (tabs.length > 0) {
    await vscode.window.tabGroups.close(tabs);
  }
}

function isUriBackedTab(input) {
  return Boolean(input) && typeof input === 'object' && 'uri' in input && input.uri instanceof vscode.Uri;
}

async function openFile(filePath) {
  const document = await vscode.workspace.openTextDocument(filePath);
  await vscode.window.showTextDocument(document);
}

function formatError(error) {
  if (error instanceof Error && error.message) {
    return error.message;
  }

  return 'Cottage setup failed.';
}

module.exports = {
  activate,
  deactivate,
};