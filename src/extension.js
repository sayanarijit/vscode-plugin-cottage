const vscode = require("vscode");
const fs = require("fs/promises");
const { constants: fsConstants } = require("fs");
const path = require("path");
const os = require("os");
const { spawn } = require("child_process");

const LEGACY_CLEAN_COMMAND = "ctg clean -qqq";
const DECRYPTED_SCHEME = "cottage";
const ENCRYPTED_FILE_VIEW_TYPE = "cottage.encryptedFileViewer";
const DENY_SCRIPT_RELATIVE_PATH = path.join(
  ".github",
  "hooks",
  "scripts",
  "deny_ctg_command.py",
);
const CTG_POLICY_RELATIVE_PATH = path.join(
  ".github",
  "hooks",
  "ctg-policy.json",
);
const CLAUDE_SETTINGS_RELATIVE_PATH = path.join(".claude", "settings.json");
const CLAUDE_DENY_SECRETS_RELATIVE_PATH = path.join(
  ".claude",
  "hooks",
  "deny-secrets.py",
);
const ENCRYPTED_FILE_SUFFIX = ".cott.age";

const DENY_SCRIPT_CONTENT = `#!/usr/bin/env python3

import json
import os
import re
import sys


TERMINAL_TOOL_NAMES = {
    "bash",
    "run_in_terminal",
    "runinterminal",
    "terminal",
    "shell",
}

  COTT_SUFFIX = re.compile(r"\\.cott\\.[^./\\\\]+$")
  TOKEN_RE = re.compile(r"""[^\s"'\`|;&<>()]+""")
  PATH_KEY_HINT = re.compile(r"path|file|dir|target|absolute", re.IGNORECASE)


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


def _repo_root(hint=None):
  d = os.path.abspath(hint) if hint and os.path.isdir(hint) else os.getcwd()
  while True:
    if os.path.isdir(os.path.join(d, ".git")) or os.path.isdir(os.path.join(d, ".cottage")):
      return d
    parent = os.path.dirname(d)
    if parent == d:
      return os.path.abspath(hint or os.getcwd())
    d = parent


def _is_sensitive(path, root):
  if not isinstance(path, str):
    return False
  path = path.strip().strip("'\"")
  if not path or len(path) > 4096 or "\n" in path:
    return False
  normalized = path.replace("\\", "/")
  if ".cottage" in [p for p in normalized.split("/") if p]:
    return True
  if COTT_SUFFIX.search(normalized):
    return True
  abs_path = path if os.path.isabs(path) else os.path.join(root, path)
  try:
    return os.path.exists(abs_path + ".cott.age")
  except OSError:
    return False


def _find_sensitive_in_command(command, root):
  if not command:
    return None
  for token in TOKEN_RE.findall(command):
    if _is_sensitive(token, root):
      return token
  return None


def _find_sensitive(value, root, path_context=False):
  """Only treat strings as path candidates when reached through a
  path/file/dir-hinted key (e.g. readFile/createFile/editFiles path
  arguments), so file content that merely mentions .cottage or
  *.cott.* in prose is never mistaken for a path to protect."""
  if isinstance(value, str):
    return value if path_context and _is_sensitive(value, root) else None
  if isinstance(value, dict):
    for key, nested in value.items():
      hit = _find_sensitive(nested, root, bool(PATH_KEY_HINT.search(str(key))))
      if hit:
        return hit
  elif isinstance(value, list):
    for nested in value:
      hit = _find_sensitive(nested, root, path_context)
      if hit:
        return hit
  return None


def _deny(reason, additional_context=None):
  output = {
    "hookSpecificOutput": {
      "hookEventName": "PreToolUse",
      "permissionDecision": "deny",
      "permissionDecisionReason": reason,
    }
  }
  if additional_context:
    output["hookSpecificOutput"]["additionalContext"] = additional_context
  json.dump(output, sys.stdout)
  sys.stdout.write("\\n")


SECRET_REASON = (
  "Blocked by cottage workspace policy: '{}' is a protected secret "
  "(inside .cottage/, matches *.cott.*, or is a decrypted file with a "
  ".cott.age counterpart). AI agents must not view or edit it."
)


def main():
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0

    tool_name = _normalize_tool_name(payload.get("tool_name"))
    tool_input = payload.get("tool_input")
    root = _repo_root(payload.get("cwd"))

    if tool_name in TERMINAL_TOOL_NAMES:
      command = _extract_command(tool_input)

      if re.match(r"^ctg(?:\\s|$)", command):
        _deny(
          "Direct ctg shell commands are blocked by workspace policy; rely on the session hooks instead.",
          additional_context=(
            "Secrets are only ever decrypted in memory by the editor extension; agents never need to run ctg."
          ),
        )
        return 0

      hit = _find_sensitive_in_command(command, root)
      if hit:
        _deny(SECRET_REASON.format(hit))
        return 0

    hit = _find_sensitive(tool_input, root)
    if hit:
      _deny(SECRET_REASON.format(hit))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
`;

  const CLAUDE_DENY_SECRETS_CONTENT = `#!/usr/bin/env python3
  import json
  import os
  import re
  import sys

  COTT_SUFFIX = re.compile(r"\\.cott\\.[^./\\\\]+$")
  TOKEN_RE = re.compile(r"""[^\s"'\`|;&<>()]+""")
  PATH_KEY_HINT = re.compile(r"path|file|dir|target|absolute", re.IGNORECASE)


  def repo_root(hint=None):
    if hint and os.path.isdir(hint):
      d = os.path.abspath(hint)
    else:
      d = os.getcwd()
    while True:
      if os.path.isdir(os.path.join(d, ".git")) or os.path.isdir(os.path.join(d, ".cottage")):
        return d
      parent = os.path.dirname(d)
      if parent == d:
        return os.path.abspath(hint or os.getcwd())
      d = parent


  def is_sensitive(path, root):
    if not isinstance(path, str):
      return False
    path = path.strip().strip("'\"")
    if not path or len(path) > 4096 or "\n" in path:
      return False
    normalized = path.replace("\\", "/")
    if ".cottage" in [p for p in normalized.split("/") if p]:
      return True
    if COTT_SUFFIX.search(normalized):
      return True
    abs_path = path if os.path.isabs(path) else os.path.join(root, path)
    try:
      return os.path.exists(abs_path + ".cott.age")
    except OSError:
      return False


  def find_sensitive(value, root, path_context=False):
    """Only treat strings as path candidates when reached through a
    path/file/dir-hinted key, so file *content* being written or edited
    (which may legitimately mention .cottage or *.cott.* in prose) is
    never mistaken for a path to protect."""
    if isinstance(value, str):
      return value if path_context and is_sensitive(value, root) else None
    if isinstance(value, dict):
      for key, nested in value.items():
        hit = find_sensitive(nested, root, bool(PATH_KEY_HINT.search(str(key))))
        if hit:
          return hit
    elif isinstance(value, list):
      for nested in value:
        hit = find_sensitive(nested, root, path_context)
        if hit:
          return hit
    return None


  def find_sensitive_in_command(command, root):
    if not command:
      return None
    for token in TOKEN_RE.findall(command):
      if is_sensitive(token, root):
        return token
    return None


  def deny(reason):
    print(
      json.dumps(
        {
          "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
          }
        }
      )
    )


  REASON = (
    "Blocked by cottage workspace policy: '{}' is a protected secret "
    "(inside .cottage/, matches *.cott.*, or is a decrypted file with a "
    ".cott.age counterpart). AI agents must not view or edit it."
  )


  def main():
    try:
      data = json.loads(sys.stdin.read() or "{}")
    except json.JSONDecodeError:
      return 0

    root = repo_root(data.get("cwd"))
    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})

    hit = None
    if tool_name == "Bash":
      hit = find_sensitive_in_command(tool_input.get("command", ""), root)
    else:
      hit = find_sensitive(tool_input, root)

    if hit:
      deny(REASON.format(hit))

    return 0


  if __name__ == "__main__":
    raise SystemExit(main())
  `;

function activate(context) {
  context.subscriptions.push(
    vscode.workspace.registerFileSystemProvider(
      DECRYPTED_SCHEME,
      new DecryptedFileSystemProvider(),
      { isCaseSensitive: process.platform !== "win32" },
    ),
    vscode.window.registerCustomEditorProvider(
      ENCRYPTED_FILE_VIEW_TYPE,
      createEncryptedFileEditorProvider(),
      {
        supportsMultipleEditorsPerDocument: false,
      },
    ),
    vscode.commands.registerCommand(
      "cottage.installAndSecureWorkspace",
      async (uri) => {
        await runInstallAndSecure(uri);
      },
    ),
    vscode.commands.registerCommand("cottage.secureWorkspace", async (uri) => {
      await runSecureWorkspace(uri);
    }),
    vscode.commands.registerCommand("cottage.encryptFile", async (uri) => {
      await runEncryptFile(uri);
    }),
    vscode.workspace.onDidOpenTextDocument((document) => {
      void handleDocumentOpened(document);
    }),
  );

  void initializeEncryptedDocumentHandling();
}

function deactivate() {}

// Serves decrypted content from memory only: reads run `ctg cat -- <enc>` and
// writes pipe the buffer to the stdin of `ctg tee -- <enc>`. Nothing plaintext
// ever touches the disk.
class DecryptedFileSystemProvider {
  constructor() {
    this._emitter = new vscode.EventEmitter();
    this.onDidChangeFile = this._emitter.event;
  }

  watch() {
    return new vscode.Disposable(() => {});
  }

  async stat(uri) {
    const stats = await fs.stat(getEncryptedPathForDecryptedUri(uri));
    return {
      type: vscode.FileType.File,
      ctime: stats.ctimeMs,
      mtime: stats.mtimeMs,
      size: stats.size,
    };
  }

  readDirectory() {
    throw vscode.FileSystemError.NoPermissions("Not a directory.");
  }

  createDirectory() {
    throw vscode.FileSystemError.NoPermissions("Not supported.");
  }

  async readFile(uri) {
    const encryptedPath = getEncryptedPathForDecryptedUri(uri);
    return runCommand(
      "ctg",
      ["cat", "--", encryptedPath],
      path.dirname(encryptedPath),
    );
  }

  async writeFile(uri, content) {
    const encryptedPath = getEncryptedPathForDecryptedUri(uri);
    if (content.byteLength === 0) {
      // ctg treats empty stdin as a request to decrypt.
      throw new Error("Refusing to encrypt empty content.");
    }

    await runCommand(
      "ctg",
      ["tee", "--", encryptedPath],
      path.dirname(encryptedPath),
      Buffer.from(content),
    );
    this._emitter.fire([{ type: vscode.FileChangeType.Changed, uri }]);
  }

  delete() {
    throw vscode.FileSystemError.NoPermissions("Not supported.");
  }

  rename() {
    throw vscode.FileSystemError.NoPermissions("Not supported.");
  }
}

function getDecryptedUri(encryptedPath) {
  return vscode.Uri.file(getDecryptedPath(encryptedPath)).with({
    scheme: DECRYPTED_SCHEME,
  });
}

function getEncryptedPathForDecryptedUri(uri) {
  return `${uri.with({ scheme: "file" }).fsPath}${ENCRYPTED_FILE_SUFFIX}`;
}

function createEncryptedFileEditorProvider() {
  return {
    async openCustomDocument(uri) {
      return {
        uri,
        dispose() {},
      };
    },
    async resolveCustomEditor(document, webviewPanel) {
      webviewPanel.webview.options = {
        enableScripts: false,
      };
      webviewPanel.webview.html = getEncryptedEditorHtml(
        "Opening encrypted file...",
      );

      try {
        await openDecryptedDocument(document.uri);
      } catch (error) {
        webviewPanel.webview.html = getEncryptedEditorHtml(formatError(error));
      }
    },
  };
}

async function initializeEncryptedDocumentHandling() {
  for (const document of vscode.workspace.textDocuments) {
    await handleDocumentOpened(document);
  }
}

async function handleDocumentOpened(document) {
  if (!isEncryptedDocument(document)) {
    return;
  }

  await openDecryptedDocument(document.uri);
}

async function openDecryptedDocument(uri) {
  try {
    const document = await vscode.workspace.openTextDocument(
      getDecryptedUri(uri.fsPath),
    );
    await vscode.window.showTextDocument(document, {
      preview: false,
      preserveFocus: false,
    });

    await closeTabsForUri(uri);
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
        title: "Cottage",
        cancellable: false,
      },
      async (progress) => {
        const installSummary = await ensureCtgInstalled(
          folder.uri.fsPath,
          progress,
        );

        progress.report({
          message: "Writing workspace AI safety policy files",
        });
        const writeSummary = await secureWorkspace(folder.uri.fsPath);

        return {
          installSummary,
          writeSummary,
        };
      },
    );

    const message = `${result.installSummary} ${result.writeSummary}`;
    const action = await vscode.window.showInformationMessage(
      message,
      "Open policy file",
      "Open settings file",
    );

    if (action === "Open policy file") {
      await openFile(path.join(folder.uri.fsPath, CTG_POLICY_RELATIVE_PATH));
    }

    if (action === "Open settings file") {
      await openFile(
        path.join(folder.uri.fsPath, CLAUDE_SETTINGS_RELATIVE_PATH),
      );
    }
  } catch (error) {
    vscode.window.showErrorMessage(formatError(error));
  }
}

async function runEncryptFile(uri) {
  const targetUri = getTargetFileUri(uri);
  if (!targetUri) {
    vscode.window.showErrorMessage("Select a file to encrypt with cottage.");
    return;
  }

  const targetFilePath = targetUri.fsPath;
  if (targetFilePath.endsWith(ENCRYPTED_FILE_SUFFIX)) {
    vscode.window.showErrorMessage(
      "The selected file is already a cottage-encrypted file.",
    );
    return;
  }

  try {
    const stats = await fs.stat(targetFilePath);
    if (!stats.isFile()) {
      vscode.window.showErrorMessage(
        "Encrypt with Cottage only supports files.",
      );
      return;
    }
  } catch (error) {
    vscode.window.showErrorMessage(formatError(error));
    return;
  }

  const workspaceFolder = vscode.workspace.getWorkspaceFolder(targetUri);
  const workspaceRoot = workspaceFolder ? workspaceFolder.uri.fsPath : null;
  const fileDirectory = path.dirname(targetFilePath);

  try {
    const openDocument = findOpenDocument(targetFilePath);
    if (openDocument && openDocument.isDirty) {
      const saved = await openDocument.save();
      if (!saved || openDocument.isDirty) {
        throw new Error(
          `Failed to save ${path.basename(targetFilePath)} before encryption.`,
        );
      }
    }

    const result = await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: "Cottage",
        cancellable: false,
      },
      async (progress) => {
        const installSummary = await ensureCtgInstalled(
          workspaceRoot || fileDirectory,
          progress,
        );
        const cottageRoot = await resolveCottageRoot(
          fileDirectory,
          workspaceRoot,
        );
        const initSummary = await ensureCottageInitialized(
          cottageRoot,
          progress,
        );

        progress.report({
          message: `Encrypting ${path.basename(targetFilePath)}`,
        });
        await runCommand("ctg", ["encrypt", "--", targetFilePath], cottageRoot);

        return {
          installSummary,
          initSummary,
        };
      },
    );

    const encryptedFilePath = `${targetFilePath}${ENCRYPTED_FILE_SUFFIX}`;
    const encryptedUri = vscode.Uri.file(encryptedFilePath);

    const parts = [
      result.installSummary,
      result.initSummary,
      `Encrypted ${path.basename(targetFilePath)} with cottage.`,
    ].filter(Boolean);
    vscode.window.showInformationMessage(parts.join(" "));

    await vscode.commands.executeCommand("vscode.open", encryptedUri);
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
        title: "Cottage",
        cancellable: false,
      },
      async (progress) => {
        progress.report({
          message: "Writing workspace AI safety policy files",
        });
        return secureWorkspace(folder.uri.fsPath);
      },
    );

    vscode.window.showInformationMessage(summary);
  } catch (error) {
    vscode.window.showErrorMessage(formatError(error));
  }
}

async function secureWorkspace(workspaceRoot) {
  const policyPath = path.join(workspaceRoot, CTG_POLICY_RELATIVE_PATH);
  const denyScriptPath = path.join(workspaceRoot, DENY_SCRIPT_RELATIVE_PATH);
  const claudeSettingsPath = path.join(
    workspaceRoot,
    CLAUDE_SETTINGS_RELATIVE_PATH,
  );
  const claudeDenySecretsPath = path.join(
    workspaceRoot,
    CLAUDE_DENY_SECRETS_RELATIVE_PATH,
  );

  await fs.mkdir(path.dirname(policyPath), { recursive: true });
  await fs.mkdir(path.dirname(denyScriptPath), { recursive: true });
  await fs.mkdir(path.dirname(claudeSettingsPath), { recursive: true });
  await fs.mkdir(path.dirname(claudeDenySecretsPath), { recursive: true });

  const policyChange = await mergeJsonFile(policyPath, mergeCopilotPolicy);
  const settingsChange = await mergeJsonFile(
    claudeSettingsPath,
    mergeClaudeSettings,
  );
  const denyScriptChange = await writeTextFile(
    denyScriptPath,
    DENY_SCRIPT_CONTENT,
    0o755,
  );
  const claudeDenySecretsChange = await writeTextFile(
    claudeDenySecretsPath,
    CLAUDE_DENY_SECRETS_CONTENT,
    0o755,
  );

  const changes = [
    policyChange,
    settingsChange,
    denyScriptChange,
    claudeDenySecretsChange,
  ].filter((change) => change.changed).length;
  if (changes === 0) {
    return "Workspace safety files were already up to date.";
  }

  return `Updated ${changes} workspace safety file${changes === 1 ? "" : "s"}.`;
}

function mergeCopilotPolicy(existing) {
  const root = asObject(existing);
  const hooks = asObject(root.hooks);

  removeLegacyCleanHooks(hooks, "SessionStart");
  removeLegacyCleanHooks(hooks, "UserPromptSubmit");
  hooks.PreToolUse = ensureHookCommand(
    hooks.PreToolUse,
    {
      type: "command",
      command: "python3 .github/hooks/scripts/deny_ctg_command.py",
      timeout: 15,
    },
    ["type", "command"],
  );

  return {
    ...root,
    hooks,
  };
}

function mergeClaudeSettings(existing) {
  const root = asObject(existing);
  const permissions = asObject(root.permissions);
  const deny = Array.isArray(permissions.deny)
    ? permissions.deny.filter((item) => typeof item === "string")
    : [];

  const requiredDenyEntries = [
    "Bash(ctg*)",
    "Read(.cottage/**)",
    "Read(**/.cottage/**)",
    "Edit(.cottage/**)",
    "Edit(**/.cottage/**)",
    "Write(.cottage/**)",
    "Write(**/.cottage/**)",
    "Read(**/*.cott.*)",
    "Edit(**/*.cott.*)",
    "Write(**/*.cott.*)",
  ];

  for (const entry of requiredDenyEntries) {
    if (!deny.includes(entry)) {
      deny.push(entry);
    }
  }

  const hooks = asObject(root.hooks);
  removeLegacyCleanHooks(hooks, "SessionStart");
  removeLegacyCleanHooks(hooks, "UserPromptSubmit");
  hooks.PreToolUse = ensureClaudeHookBlock(hooks.PreToolUse, {
    matcher: "Read|Edit|Write|MultiEdit|NotebookEdit|Bash",
    hooks: [
      {
        type: "command",
        command: "python3 \"$(git rev-parse --show-toplevel)/.claude/hooks/deny-secrets.py\"",
      },
    ],
  });

  return {
    ...root,
    permissions: {
      ...permissions,
      deny,
    },
    hooks,
  };
}

// Secrets are decrypted in memory only, so the old `ctg clean` hooks written by
// earlier versions are no longer needed.
function removeLegacyCleanHooks(hooks, eventName) {
  if (!Array.isArray(hooks[eventName])) {
    return;
  }

  const remaining = hooks[eventName].filter((entry) => {
    if (!isPlainObject(entry)) {
      return true;
    }
    if (entry.command === LEGACY_CLEAN_COMMAND) {
      return false;
    }
    return !(
      Array.isArray(entry.hooks) &&
      entry.hooks.length > 0 &&
      entry.hooks.every((hook) => hook && hook.command === LEGACY_CLEAN_COMMAND)
    );
  });

  if (remaining.length > 0) {
    hooks[eventName] = remaining;
  } else {
    delete hooks[eventName];
  }
}

function ensureClaudeHookBlock(existingValue, desiredEntry) {
  const entries = Array.isArray(existingValue)
    ? existingValue.filter(isPlainObject)
    : [];
  const desiredJson = JSON.stringify(desiredEntry);
  const remaining = entries.filter(
    (entry) => JSON.stringify(entry) !== desiredJson,
  );

  remaining.push(desiredEntry);
  return remaining;
}

function ensureHookCommand(existingValue, desiredEntry, identityKeys) {
  const entries = Array.isArray(existingValue)
    ? existingValue.filter(isPlainObject)
    : [];
  const desiredIdentity = JSON.stringify(
    identityKeys.map((key) => desiredEntry[key] ?? null),
  );
  const remaining = entries.filter((entry) => {
    const entryIdentity = JSON.stringify(
      identityKeys.map((key) => entry[key] ?? null),
    );
    return entryIdentity !== desiredIdentity;
  });

  remaining.push(desiredEntry);
  return remaining;
}

async function mergeJsonFile(filePath, mergeFn) {
  let existing = {};
  let hadExistingFile = false;

  try {
    const raw = await fs.readFile(filePath, "utf8");
    existing = JSON.parse(raw);
    hadExistingFile = true;
  } catch (error) {
    if (error && error.code !== "ENOENT") {
      throw new Error(
        `Failed to read ${path.basename(filePath)}: ${error.message}`,
      );
    }
  }

  const nextValue = mergeFn(existing);
  const nextContent = `${JSON.stringify(nextValue, null, 2)}${os.EOL}`;

  if (hadExistingFile) {
    const currentContent = await fs.readFile(filePath, "utf8");
    if (currentContent === nextContent) {
      return { changed: false };
    }
  }

  await fs.writeFile(filePath, nextContent, "utf8");
  return { changed: true };
}

async function writeTextFile(filePath, content, mode) {
  let currentContent = null;

  try {
    currentContent = await fs.readFile(filePath, "utf8");
  } catch (error) {
    if (error && error.code !== "ENOENT") {
      throw new Error(
        `Failed to read ${path.basename(filePath)}: ${error.message}`,
      );
    }
  }

  if (currentContent === content) {
    return { changed: false };
  }

  await fs.writeFile(filePath, content, "utf8");
  if (typeof mode === "number") {
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
    vscode.window.showErrorMessage(
      "Open a workspace folder before configuring cottage.",
    );
    return null;
  }

  if (folders.length === 1) {
    return folders[0];
  }

  const picked = await vscode.window.showWorkspaceFolderPick({
    placeHolder: "Select the workspace to secure with cottage",
  });

  return picked || null;
}

async function detectBestInstaller() {
  const candidates = [
    {
      label: "cargo binstall (crates.io binary)",
      command: "cargo",
      args: ["binstall", "--locked", "cottage", "-y"],
      available: async () => {
        if (!(await findExecutable("cargo"))) {
          return false;
        }

        return commandSucceeds("cargo", ["binstall", "--help"]);
      },
    },
    {
      label: "cargo install (crates.io source)",
      command: "cargo",
      args: ["install", "--locked", "cottage"],
      available: async () => Boolean(await findExecutable("cargo")),
    },
    {
      label: "uv tool install (PyPI)",
      command: "uv",
      args: ["tool", "install", "--force", "cottage"],
      available: async () => Boolean(await findExecutable("uv")),
    },
    {
      label: "pipx install (PyPI)",
      command: "pipx",
      args: ["install", "--force", "cottage"],
      available: async () => {
        if (!(await findExecutable("pipx"))) {
          return false;
        }

        return commandSucceeds("pipx", ["--version"]);
      },
    },
    {
      label: "python3 -m pip (PyPI user install)",
      command: "python3",
      args: ["-m", "pip", "install", "--user", "cottage"],
      available: async () => {
        if (!(await findExecutable("python3"))) {
          return false;
        }

        return commandSucceeds("python3", ["-m", "pip", "--version"]);
      },
    },
    {
      label: "pnpm global add (npm registry)",
      command: "pnpm",
      args: ["add", "-g", "@sayanarijit/cottage"],
      available: async () => Boolean(await findExecutable("pnpm")),
    },
    {
      label: "yarn global add (npm registry)",
      command: "yarn",
      args: ["global", "add", "@sayanarijit/cottage"],
      available: async () => Boolean(await findExecutable("yarn")),
    },
    {
      label: "npm global install (npm registry)",
      command: "npm",
      args: ["install", "-g", "@sayanarijit/cottage"],
      available: async () => Boolean(await findExecutable("npm")),
    },
  ];

  for (const candidate of candidates) {
    if (await candidate.available()) {
      return candidate;
    }
  }

  return null;
}

async function ensureCtgInstalled(workingDirectory, progress) {
  progress.report({ message: "Checking for an existing ctg installation" });

  if (await findExecutable("ctg")) {
    return "ctg is already available on PATH.";
  }

  progress.report({
    message: "Detecting the best installer for this environment",
  });
  const candidate = await detectBestInstaller();
  if (!candidate) {
    throw new Error(
      "No supported installer was found. Expected one of: cargo, uv, pipx, python3, pnpm, yarn, or npm.",
    );
  }

  progress.report({ message: `Installing cottage via ${candidate.label}` });
  await runCommand(candidate.command, candidate.args, workingDirectory);

  if (!(await findExecutable("ctg"))) {
    throw new Error(
      "Installed cottage, but ctg is not visible to VS Code yet. Restart VS Code and try again.",
    );
  }

  return `Installed cottage via ${candidate.label}.`;
}

async function resolveCottageRoot(fileDirectory, workspaceRoot) {
  const existingRoot = await findNearestCottageRoot(
    fileDirectory,
    workspaceRoot,
  );
  if (existingRoot) {
    return existingRoot;
  }

  return workspaceRoot || fileDirectory;
}

async function ensureCottageInitialized(cottageRoot, progress) {
  if (await pathExists(path.join(cottageRoot, ".cottage"))) {
    return "Cottage is already initialized for this workspace.";
  }

  progress.report({ message: "Initializing cottage in this workspace" });
  await runCommand("ctg", ["init"], cottageRoot);
  return "Initialized cottage in this workspace.";
}

async function runCommand(command, args, cwd, input) {
  const executablePath = await findExecutable(command);
  if (!executablePath) {
    throw new Error(`Unable to find executable: ${command}`);
  }

  return new Promise((resolve, reject) => {
    const child = spawn(executablePath, args, {
      cwd,
      env: process.env,
      shell: false,
      stdio: [input ? "pipe" : "ignore", "pipe", "pipe"],
    });

    const stdout = [];
    let stderr = "";

    child.stdout.on("data", (chunk) => {
      stdout.push(chunk);
    });

    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    child.on("error", (error) => {
      reject(error);
    });

    child.on("close", (code) => {
      if (code === 0) {
        resolve(Buffer.concat(stdout));
        return;
      }

      reject(new Error(stderr.trim() || `${command} exited with code ${code}`));
    });

    if (input) {
      child.stdin.on("error", () => {});
      child.stdin.end(input);
    }
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
  const pathParts = getExecutableSearchDirectories();
  const executableNames = getExecutableNames(command);

  for (const directory of pathParts) {
    for (const executableName of executableNames) {
      const candidatePath = path.join(directory, executableName);
      try {
        await fs.access(candidatePath, fsConstants.X_OK);
        return candidatePath;
      } catch {
        continue;
      }
    }
  }

  return null;
}

function getExecutableSearchDirectories() {
  const directories = new Set(
    (process.env.PATH || "").split(path.delimiter).filter(Boolean),
  );
  const homeDirectory = os.homedir();

  if (process.platform !== "win32" && homeDirectory) {
    directories.add(path.join(homeDirectory, ".cargo", "bin"));
    directories.add(path.join(homeDirectory, ".local", "bin"));
    directories.add(path.join(homeDirectory, ".npm-global", "bin"));
    directories.add(
      path.join(
        homeDirectory,
        ".config",
        "yarn",
        "global",
        "node_modules",
        ".bin",
      ),
    );
    directories.add(path.join(homeDirectory, ".yarn", "bin"));
    directories.add(path.join(homeDirectory, ".local", "share", "pnpm"));
    directories.add(path.join(homeDirectory, "bin"));
  }

  return Array.from(directories);
}

async function pathExists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function findNearestCottageRoot(startDirectory, stopDirectory) {
  let currentDirectory = path.resolve(startDirectory);
  const resolvedStopDirectory = stopDirectory
    ? path.resolve(stopDirectory)
    : null;

  while (true) {
    if (await pathExists(path.join(currentDirectory, ".cottage"))) {
      return currentDirectory;
    }

    if (
      resolvedStopDirectory &&
      normalizeTrackedPath(currentDirectory) ===
        normalizeTrackedPath(resolvedStopDirectory)
    ) {
      return null;
    }

    const parentDirectory = path.dirname(currentDirectory);
    if (parentDirectory === currentDirectory) {
      return null;
    }

    currentDirectory = parentDirectory;
  }
}

function getExecutableNames(command) {
  if (process.platform !== "win32") {
    return [command];
  }

  const extensions = (process.env.PATHEXT || ".EXE;.CMD;.BAT;.COM")
    .split(";")
    .filter(Boolean)
    .map((extension) => extension.toLowerCase());

  return [command, ...extensions.map((extension) => `${command}${extension}`)];
}

function asObject(value) {
  return isPlainObject(value) ? { ...value } : {};
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isEncryptedDocument(document) {
  return (
    document.uri.scheme === "file" &&
    document.fileName.endsWith(ENCRYPTED_FILE_SUFFIX)
  );
}

function getTargetFileUri(uri) {
  if (uri && uri.scheme === "file") {
    return uri;
  }

  const activeDocument =
    vscode.window.activeTextEditor && vscode.window.activeTextEditor.document;
  if (activeDocument && activeDocument.uri.scheme === "file") {
    return activeDocument.uri;
  }

  return null;
}

function getDecryptedPath(encryptedPath) {
  if (!encryptedPath.endsWith(ENCRYPTED_FILE_SUFFIX)) {
    return null;
  }

  return encryptedPath.slice(0, -ENCRYPTED_FILE_SUFFIX.length);
}

function normalizeTrackedPath(filePath) {
  return process.platform === "win32" ? filePath.toLowerCase() : filePath;
}

function findOpenDocument(filePath) {
  return vscode.workspace.textDocuments.find(
    (document) =>
      document.uri.scheme === "file" &&
      normalizeTrackedPath(document.uri.fsPath) ===
        normalizeTrackedPath(filePath),
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
  return (
    Boolean(input) &&
    typeof input === "object" &&
    "uri" in input &&
    input.uri instanceof vscode.Uri
  );
}

function getEncryptedEditorHtml(message) {
  const safeMessage = escapeHtml(message);
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Cottage</title>
  <style>
    body {
      margin: 0;
      font-family: var(--vscode-font-family);
      background: var(--vscode-editor-background);
      color: var(--vscode-editor-foreground);
      display: grid;
      place-items: center;
      min-height: 100vh;
    }

    p {
      margin: 0;
      padding: 0 24px;
      text-align: center;
      line-height: 1.5;
    }
  </style>
</head>
<body>
  <p>${safeMessage}</p>
</body>
</html>`;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

async function openFile(filePath) {
  const document = await vscode.workspace.openTextDocument(filePath);
  await vscode.window.showTextDocument(document);
}

function formatError(error) {
  if (error instanceof Error && error.message) {
    return error.message;
  }

  return "Cottage setup failed.";
}

module.exports = {
  activate,
  deactivate,
};
