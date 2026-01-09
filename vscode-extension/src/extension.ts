/**
 * Falco Rules VS Code Extension
 *
 * Provides comprehensive language support for Falco Security Rules including:
 * - Syntax highlighting for .falco.yaml and .falco.yml files
 * - Intelligent code completion for rules, macros, lists, and fields
 * - Hover information for Falco fields and symbols
 * - Go-to-definition for macros and lists
 * - Real-time diagnostics and validation
 * - JSON Schema validation for YAML files
 *
 * @license Apache-2.0
 * @see https://falco.org
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { workspace, window, commands, StatusBarAlignment, languages, Uri } from 'vscode';
import type { ExtensionContext, OutputChannel, StatusBarItem } from 'vscode';
import { LanguageClient, State } from 'vscode-languageclient/node.js';
import type {
  LanguageClientOptions,
  ServerOptions,
  Executable,
} from 'vscode-languageclient/node.js';

let client: LanguageClient | undefined;
let outputChannel: OutputChannel;
let statusBarItem: StatusBarItem;

/**
 * Extension activation
 */
export async function activate(context: ExtensionContext): Promise<void> {
  // Create output channel
  outputChannel = window.createOutputChannel('Falco Rules');
  context.subscriptions.push(outputChannel);

  // Create status bar item
  statusBarItem = window.createStatusBarItem(StatusBarAlignment.Right, 100);
  statusBarItem.text = '$(shield) Falco';
  statusBarItem.tooltip = 'Falco Rules Language Server';
  statusBarItem.command = 'falco.showOutput';
  context.subscriptions.push(statusBarItem);

  // Register commands
  registerCommands(context);

  // Start language server
  await startLanguageServer(context);

  outputChannel.appendLine('Falco Rules extension activated');
}

/**
 * Extension deactivation
 */
export async function deactivate(): Promise<void> {
  if (client) {
    await client.stop();
  }
}

/**
 * Register extension commands
 */
function registerCommands(context: ExtensionContext): void {
  // Show output channel
  context.subscriptions.push(
    commands.registerCommand('falco.showOutput', () => {
      outputChannel.show();
      return null;
    })
  );

  // Restart language server
  context.subscriptions.push(
    commands.registerCommand('falco.restartServer', async () => {
      try {
        if (client) {
          await client.stop();
          client = undefined;
        }
        await startLanguageServer(context);
        window.showInformationMessage('Falco language server restarted');
        return null; // Explicitly return null to satisfy VS Code command protocol
      } catch (error) {
        window.showErrorMessage(`Failed to restart language server: ${error}`);
        return null;
      }
    })
  );

  // Validate current file
  context.subscriptions.push(
    commands.registerCommand('falco.validate', async () => {
      const editor = window.activeTextEditor;
      if (!editor) {
        window.showWarningMessage('No active editor');
        return null;
      }

      const langId = editor.document.languageId;
      if (langId !== 'falco' && langId !== 'falco-yaml') {
        window.showWarningMessage('Current file is not a Falco rules file');
        return null;
      }

      // The language server validates on every change, but we can force a re-save
      // to trigger a fresh validation cycle
      if (editor.document.isDirty) {
        await editor.document.save();
      }
      window.showInformationMessage('Validation completed');
      return null;
    })
  );

  // Validate workspace
  context.subscriptions.push(
    commands.registerCommand('falco.validateWorkspace', async () => {
      outputChannel.clear();
      outputChannel.show(true); // Show but don't focus
      outputChannel.appendLine('='.repeat(80));
      outputChannel.appendLine('Falco Workspace Validation');
      outputChannel.appendLine('='.repeat(80));
      outputChannel.appendLine('');

      const yamlFiles = await workspace.findFiles('**/*.falco.yaml');
      const ymlFiles = await workspace.findFiles('**/*.falco.yml');
      const allFiles = [...yamlFiles, ...ymlFiles];

      if (allFiles.length === 0) {
        outputChannel.appendLine('❌ No Falco rules files found in workspace');
        window.showInformationMessage('No Falco rules files found in workspace');
        return null;
      }

      outputChannel.appendLine(`📁 Found ${allFiles.length} Falco rules file(s)\n`);

      // Open each file to trigger validation
      let validatedCount = 0;
      const fileResults: Array<{ uri: Uri; errors: number; warnings: number; infos: number }> = [];

      for (const fileUri of allFiles) {
        try {
          await workspace.openTextDocument(fileUri);
          validatedCount++;

          // Wait a bit for diagnostics to be published
          await new Promise(resolve => setTimeout(resolve, 100));

          // Get diagnostics for this file
          const diagnostics = languages.getDiagnostics(fileUri);
          const errors = diagnostics.filter(d => d.severity === 0).length; // Error = 0
          const warnings = diagnostics.filter(d => d.severity === 1).length; // Warning = 1
          const infos = diagnostics.filter(d => d.severity === 2 || d.severity === 3).length; // Info/Hint

          fileResults.push({ uri: fileUri, errors, warnings, infos });
        } catch (error) {
          outputChannel.appendLine(`❌ Failed to open: ${fileUri.fsPath}`);
          outputChannel.appendLine(`   Error: ${error}\n`);
        }
      }

      // Display results
      outputChannel.appendLine('─'.repeat(80));
      outputChannel.appendLine('Validation Results:');
      outputChannel.appendLine('─'.repeat(80));
      outputChannel.appendLine('');

      let totalErrors = 0;
      let totalWarnings = 0;
      let filesWithIssues = 0;

      for (const result of fileResults) {
        const relativePath = workspace.asRelativePath(result.uri);
        // Only count files with errors or warnings as "files with issues"
        // Infos/hints are not shown in Problems panel by default
        const hasIssues = result.errors > 0 || result.warnings > 0;

        if (hasIssues) {
          filesWithIssues++;
          const icon = result.errors > 0 ? '❌' : '⚠️';
          outputChannel.appendLine(`${icon} ${relativePath}`);

          if (result.errors > 0) {
            outputChannel.appendLine(`   🔴 ${result.errors} error(s)`);
          }
          if (result.warnings > 0) {
            outputChannel.appendLine(`   🟡 ${result.warnings} warning(s)`);
          }
          outputChannel.appendLine('');
        } else {
          outputChannel.appendLine(`✅ ${relativePath}`);
        }

        totalErrors += result.errors;
        totalWarnings += result.warnings;
      }

      // Summary
      outputChannel.appendLine('');
      outputChannel.appendLine('='.repeat(80));
      outputChannel.appendLine('Summary:');
      outputChannel.appendLine('='.repeat(80));
      outputChannel.appendLine(`📊 Total files validated: ${validatedCount}`);
      outputChannel.appendLine(`✅ Files without issues: ${validatedCount - filesWithIssues}`);
      outputChannel.appendLine(`⚠️  Files with issues: ${filesWithIssues}`);
      outputChannel.appendLine('');
      outputChannel.appendLine(`🔴 Total errors: ${totalErrors}`);
      outputChannel.appendLine(`🟡 Total warnings: ${totalWarnings}`);
      outputChannel.appendLine('='.repeat(80));

      // Show appropriate message and open Problems panel if there are errors
      if (totalErrors > 0) {
        const msg = `Validation complete: ${totalErrors} error(s), ${totalWarnings} warning(s) in ${filesWithIssues} file(s)`;
        window.showErrorMessage(msg);
        // Open Problems panel
        await commands.executeCommand('workbench.actions.view.problems');
      } else if (totalWarnings > 0) {
        const msg = `Validation complete: ${totalWarnings} warning(s) in ${filesWithIssues} file(s)`;
        window.showWarningMessage(msg);
        await commands.executeCommand('workbench.actions.view.problems');
      } else {
        window.showInformationMessage(`✅ All ${validatedCount} file(s) validated successfully!`);
      }

      return null;
    })
  );

  // Format document
  context.subscriptions.push(
    commands.registerCommand('falco.formatDocument', async () => {
      const editor = window.activeTextEditor;
      if (!editor) {
        window.showWarningMessage('No active editor');
        return null;
      }

      const langId = editor.document.languageId;
      if (langId !== 'falco' && langId !== 'falco-yaml') {
        window.showWarningMessage('Current file is not a Falco rules file');
        return null;
      }

      await commands.executeCommand('editor.action.formatDocument');
      return null;
    })
  );
}

/**
 * Find the Go binary for the language server
 */
function findGoBinary(context: ExtensionContext): string | null {
  const platform = os.platform();
  const arch = os.arch();

  // Map Node.js arch to Go arch (ensure it's always a string)
  const goArch: string = arch === 'x64' ? 'amd64' : arch === 'arm64' ? 'arm64' : 'amd64';

  // Determine platform-specific binary name
  let platformBinaryName: string;
  if (platform === 'win32') {
    platformBinaryName = `falco-lang-windows-${goArch}.exe`;
  } else if (platform === 'darwin') {
    platformBinaryName = `falco-lang-darwin-${goArch}`;
  } else if (platform === 'linux') {
    platformBinaryName = `falco-lang-linux-${goArch}`;
  } else {
    platformBinaryName = 'falco-lang'; // Fallback
  }

  // Generic binary name for fallback
  const genericBinaryName = platform === 'win32' ? 'falco-lang.exe' : 'falco-lang';

  // Check paths in order of preference:
  // 1. Bundled with extension (platform-specific)
  const bundledPlatformPath = context.asAbsolutePath(path.join('bin', platformBinaryName));
  if (fs.existsSync(bundledPlatformPath)) {
    outputChannel.appendLine(`Found bundled binary: ${bundledPlatformPath}`);
    return bundledPlatformPath;
  }

  // 2. Bundled with extension (generic name - backward compatibility)
  const bundledGenericPath = context.asAbsolutePath(path.join('bin', genericBinaryName));
  if (fs.existsSync(bundledGenericPath)) {
    outputChannel.appendLine(`Found bundled binary (generic): ${bundledGenericPath}`);
    return bundledGenericPath;
  }

  // 3. In workspace falco-lsp/build folder (development)
  const workspaceFolders = workspace.workspaceFolders;
  if (workspaceFolders) {
    for (const folder of workspaceFolders) {
      const devPath = path.join(folder.uri.fsPath, 'falco-lsp', 'build', genericBinaryName);
      if (fs.existsSync(devPath)) {
        outputChannel.appendLine(`Found development binary: ${devPath}`);
        return devPath;
      }
    }
  }

  // 4. Global install in PATH
  const pathEnv = process.env.PATH || '';
  const pathDirs = pathEnv.split(path.delimiter);
  for (const dir of pathDirs) {
    const binPath = path.join(dir, genericBinaryName);
    if (fs.existsSync(binPath)) {
      outputChannel.appendLine(`Found binary in PATH: ${binPath}`);
      return binPath;
    }
  }

  // 5. Common locations
  const commonPaths = [
    path.join(os.homedir(), 'go', 'bin', genericBinaryName),
    path.join(os.homedir(), '.local', 'bin', genericBinaryName),
    `/usr/local/bin/${genericBinaryName}`,
    `/usr/bin/${genericBinaryName}`,
  ];

  for (const p of commonPaths) {
    if (fs.existsSync(p)) {
      outputChannel.appendLine(`Found binary in common location: ${p}`);
      return p;
    }
  }

  return null;
}

/**
 * Start the Falco language server
 */
async function startLanguageServer(context: ExtensionContext): Promise<void> {
  // Find the Go binary - it's required
  const goBinaryPath = findGoBinary(context);

  if (!goBinaryPath) {
    const platform = os.platform();
    const arch = os.arch();
    const goArch: string = arch === 'x64' ? 'amd64' : arch === 'arm64' ? 'arm64' : 'amd64';
    const platformBinary =
      platform === 'win32'
        ? `falco-lang-windows-${goArch}.exe`
        : platform === 'darwin'
          ? `falco-lang-darwin-${goArch}`
          : `falco-lang-linux-${goArch}`;

    const errorMsg =
      'Falco language server binary not found. Please ensure falco-lang is installed.';
    outputChannel.appendLine(`ERROR: ${errorMsg}`);
    outputChannel.appendLine('Searched locations:');
    outputChannel.appendLine(`  - ${context.asAbsolutePath(path.join('bin', platformBinary))}`);
    outputChannel.appendLine(`  - ${context.asAbsolutePath(path.join('bin', 'falco-lang'))}`);
    outputChannel.appendLine('  - Workspace falco-lsp/build/');
    outputChannel.appendLine('  - System PATH');
    outputChannel.appendLine('  - Common install locations');
    window.showErrorMessage(errorMsg);
    return;
  }

  outputChannel.appendLine(`Found Go binary: ${goBinaryPath}`);

  // Verify binary is executable
  try {
    fs.accessSync(goBinaryPath, fs.constants.X_OK);
    outputChannel.appendLine('Binary is executable');
  } catch {
    outputChannel.appendLine('WARNING: Binary may not be executable, attempting to fix...');
    try {
      fs.chmodSync(goBinaryPath, 0o755);
      outputChannel.appendLine('Fixed binary permissions');
    } catch (chmodErr) {
      const errMsg = chmodErr instanceof Error ? chmodErr.message : String(chmodErr);
      outputChannel.appendLine(`Failed to fix permissions: ${errMsg}`);
    }
  }

  const executable: Executable = {
    command: goBinaryPath,
    args: ['lsp', '--stdio'],
  };

  const serverOptions: ServerOptions = {
    run: executable,
    debug: executable,
  };

  // Client options
  const clientOptions: LanguageClientOptions = {
    // Register for Falco documents
    documentSelector: [
      { scheme: 'file', language: 'falco-yaml' },
      { scheme: 'untitled', language: 'falco-yaml' },
    ],
    synchronize: {
      // Notify server about file changes
      fileEvents: [
        workspace.createFileSystemWatcher('**/*.falco.yaml'),
        workspace.createFileSystemWatcher('**/*.falco.yml'),
      ],
    },
    outputChannel,
    traceOutputChannel: outputChannel,
    initializationOptions: getConfiguration(),
  };

  // Create the language client
  client = new LanguageClient('falco', 'Falco Rules Language Server', serverOptions, clientOptions);

  // Handle state changes
  client.onDidChangeState(event => {
    outputChannel.appendLine(
      `Language server state changed: ${State[event.oldState]} -> ${State[event.newState]}`
    );
    switch (event.newState) {
      case State.Starting:
        statusBarItem.text = '$(loading~spin) Falco';
        statusBarItem.tooltip = 'Falco Language Server starting...';
        statusBarItem.show();
        break;
      case State.Running:
        statusBarItem.text = '$(shield) Falco';
        statusBarItem.tooltip = 'Falco Language Server running';
        statusBarItem.show();
        break;
      case State.Stopped:
        statusBarItem.text = '$(shield) Falco (stopped)';
        statusBarItem.tooltip = 'Falco Language Server stopped';
        break;
    }
  });

  // Start the client with error handling
  try {
    outputChannel.appendLine('Starting language client...');
    await client.start();
    outputChannel.appendLine('Language server started successfully');
  } catch (err) {
    const errMsg = err instanceof Error ? err.message : String(err);
    const errorMsg = `Failed to start language server: ${errMsg}`;
    outputChannel.appendLine(`ERROR: ${errorMsg}`);
    window.showErrorMessage(errorMsg);
  }
}

/**
 * Get extension configuration
 */
function getConfiguration(): Record<string, unknown> {
  const config = workspace.getConfiguration('falco');

  return {
    maxNumberOfProblems: config.get<number>('maxNumberOfProblems', 100),
    enableFormatting: config.get<boolean>('enableFormatting', true),
    tabSize: config.get<number>('tabSize', 2),
    insertSpaces: config.get<boolean>('insertSpaces', true),
    alignProperties: config.get<boolean>('alignProperties', true),
    enableSemanticHighlighting: config.get<boolean>('enableSemanticHighlighting', true),
    validateYamlFiles: config.get<boolean>('validateYamlFiles', true),
  };
}

// Export for testing
export { client, outputChannel };
