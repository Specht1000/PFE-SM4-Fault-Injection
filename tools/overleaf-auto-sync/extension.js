/* One-way sync: local disk -> the authenticated Overleaf Workshop filesystem. */
const fs = require('node:fs/promises');
const path = require('node:path');

const EXTENSIONS = new Set(['.tex', '.bib', '.sty', '.cls', '.bst', '.png', '.jpg', '.jpeg', '.svg', '.eps', '.md', '.txt']);
const DOCUMENTS = new Set(['.tex', '.bib', '.sty', '.cls', '.bst', '.md', '.txt']);
const ENTRY_MARKER = '% Managed by PFE Overleaf Auto Sync';

function entryDocument(subfolder, filename = 'main.tex') {
    if (!/^[A-Za-z0-9_/-]+$/.test(subfolder) || subfolder.split('/').some(p => !p || p === '..')) throw new Error('Unsupported remote folder name for the root entry document.');
    if (!/^(main|full_report|part_\d{2})\.tex$/.test(filename)) throw new Error('Unsupported main document name.');
    return `${ENTRY_MARKER}\n% Resolve all report inputs relative to the uploaded LaTeX folder.\n\\makeatletter\n\\def\\input@path{{${subfolder}/}}\n\\makeatother\n\\input{${subfolder}/${filename}}\n`;
}

function canonicalContent(relative, content) {
    const bytes = Buffer.from(content);
    if (!DOCUMENTS.has(path.extname(relative).toLowerCase())) return bytes;
    // Overleaf reconstructs document lines with LF; Windows disk files use CRLF.
    return Buffer.from(bytes.toString('utf8').replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n'), 'utf8');
}

async function writeRemoteContent(remote, relative, content, missing) {
    if (missing && DOCUMENTS.has(path.extname(relative).toLowerCase())) {
        // Overleaf Workshop routes nonempty new files through its upload API.
        // Create an empty document instead, then initialize the OT cache and
        // update its text through the same path used by the Overleaf editor.
        await remote.write(relative, new Uint8Array());
        await remote.read(relative);
    }
    await remote.write(relative, content);
}

function allowed(relative) {
    const parts = relative.replace(/\\/g, '/').split('/');
    return parts.length > 0 && parts.every(p => p && p !== '..' && !p.startsWith('.')) && EXTENSIONS.has(path.extname(relative).toLowerCase());
}

async function localFiles(directory, prefix = '') {
    const result = [];
    for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
        if (entry.name.startsWith('.') || entry.isSymbolicLink()) continue;
        const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
        if (entry.isDirectory()) result.push(...await localFiles(path.join(directory, entry.name), relative));
        else if (entry.isFile() && allowed(relative)) result.push(relative);
    }
    return result.sort();
}

// Shared engine is independent of VS Code so path and error handling are testable.
function createEngine(localRoot, remote, report, wait = ms => new Promise(resolve => setTimeout(resolve, ms))) {
    let queue = Promise.resolve();
    let stopped = false;

    async function sync(relative, removeMissing = false) {
        if (stopped || !allowed(relative)) return;
        const absolute = path.resolve(localRoot, relative);
        const normalized = path.relative(localRoot, absolute);
        if (path.isAbsolute(normalized) || normalized.startsWith('..')) throw new Error('File is outside the configured LaTeX folder.');
        let content;
        try {
            if (!(await fs.lstat(absolute)).isFile()) return;
            content = canonicalContent(relative, await fs.readFile(absolute));
        } catch (error) {
            if (error.code !== 'ENOENT') throw error;
            if (removeMissing && !stopped) {
                await remote.remove(relative);
                report(`Deleted: ${relative}`);
            }
            return;
        }
        let previous, missing = false;
        try { previous = await remote.read(relative); }
        catch (error) { if (error.code !== 'FileNotFound') throw error; missing = true; }
        if (previous && canonicalContent(relative, previous).equals(content)) return;
        if (stopped) return;
        report(`Syncing: ${relative}`);
        await remote.write(relative, content, { missing });
        let stored;
        // A document event may arrive just after the write acknowledgement.
        // Retry reads only: do not reapply an edit while its acknowledgement settles.
        for (const delay of [100, 200, 500, 1000]) {
            await wait(delay);
            if (stopped) return;
            stored = canonicalContent(relative, await remote.read(relative));
            if (stored.equals(content)) {
                report(`Uploaded: ${relative}`);
                return;
            }
        }
        let difference = 0;
        while (difference < Math.min(stored.length, content.length) && stored[difference] === content[difference]) difference++;
        throw new Error(`Remote verification failed: ${relative}; expected ${content.length} normalized bytes, received ${stored.length}; first difference at byte ${difference}`);
    }

    return {
        enqueue(relative, removeMissing = false) {
            const job = queue.then(() => sync(relative, removeMissing)).catch(error => {
                throw new Error(`${relative}: ${error.message || error.code || String(error)}`);
            });
            queue = job.catch(() => {});
            return job;
        },
        async uploadAll() {
            const failures = [];
            for (const relative of await localFiles(localRoot)) {
                try { await this.enqueue(relative); }
                catch (error) { report(`ERROR: ${error.message}`); failures.push(error); }
            }
            if (failures.length) throw new Error(`${failures.length} file(s) failed. ${failures[0].message}. See Output > PFE Overleaf Sync.`);
        },
        stop() { stopped = true; }
    };
}

async function activate(context) {
    const vscode = require('vscode');
    const output = vscode.window.createOutputChannel('PFE Overleaf Sync');
    const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 20);
    status.command = 'pfeOverleaf.upload';
    let engine, watcher;
    const pending = new Map();
    let lastFailure = 0;

    function failure(error) {
        output.appendLine(`ERROR: ${error.message}`);
        status.text = '$(warning) Overleaf sync failed';
        status.tooltip = 'Open Output > PFE Overleaf Sync. Reconnect or use Sync All Files Now to retry.';
        if (Date.now() - lastFailure > 30000) {
            lastFailure = Date.now();
            vscode.window.showErrorMessage(`PFE Overleaf sync: ${error.message}`);
        }
    }

    function stop() {
        engine?.stop(); engine = undefined;
        watcher?.dispose(); watcher = undefined;
        for (const timer of pending.values()) clearTimeout(timer);
        pending.clear();
        status.text = '$(debug-pause) Overleaf sync stopped';
    }

    async function start(config) {
        stop();
        const source = path.resolve(config.localFolder);
        if (!(await fs.stat(source)).isDirectory()) throw new Error('Local LaTeX folder does not exist.');
        const destination = vscode.Uri.parse(config.remoteUri);
        if (destination.scheme !== 'overleaf-workshop') throw new Error('Select a project opened through Overleaf Workshop.');
        await vscode.extensions.getExtension('iamhyc.overleaf-workshop')?.activate();
        // Probe authentication/provider before enabling the watcher.
        await vscode.workspace.fs.stat(destination);
        const uri = relative => vscode.Uri.joinPath(destination, ...relative.split('/'));
        engine = createEngine(source, {
            read: relative => vscode.workspace.fs.readFile(uri(relative)),
            async write(relative, content, options) {
                const parents = relative.split('/').slice(0, -1);
                let parent = '';
                for (const name of parents) {
                    parent = parent ? `${parent}/${name}` : name;
                    try { await vscode.workspace.fs.stat(uri(parent)); }
                    catch (error) {
                        if (error.code !== 'FileNotFound') throw error;
                        await vscode.workspace.fs.createDirectory(uri(parent));
                    }
                }
                await writeRemoteContent({
                    read: name => vscode.workspace.fs.readFile(uri(name)),
                    write: (name, bytes) => vscode.workspace.fs.writeFile(uri(name), bytes)
                }, relative, content, options?.missing);
            },
            async remove(relative) {
                try { await vscode.workspace.fs.delete(uri(relative), { recursive: false, useTrash: false }); }
                catch (error) { if (error.code !== 'FileNotFound') throw error; }
            }
        }, message => output.appendLine(`${new Date().toISOString()} ${message}`));
        const current = engine;
        async function fixMainDocument() {
            // The upload was nested under overleaf_project/, while the server
            // still tried main.tex at project root. Set a real root entry file
            // and explicitly supply the input search path for nested chapters.
            const vfs = await vscode.commands.executeCommand('remoteFileSystem.prefetch', destination);
            if (!vfs?.getValidMainDocs || !vfs?.updateSettings) throw new Error('Overleaf Workshop does not expose the main-document settings API.');
            const projectFolder = destination.path.split('/').filter(Boolean)[0];
            const rootUri = destination.with({ path: '/' + projectFolder });
            const subfolder = destination.path.split('/').filter(Boolean).slice(1).join('/');
            let filename = 'main.tex';
            if (subfolder) {
                const selected = vfs.getRootDocName();
                const prefix = '/' + subfolder + '/';
                const selectedName = selected.startsWith(prefix) ? selected.slice(prefix.length) : '';
                if (/^(main|full_report|part_\d{2})\.tex$/.test(selectedName)) filename = selectedName;
                const content = Buffer.from(entryDocument(subfolder, filename), 'utf8');
                const entryUri = vscode.Uri.joinPath(rootUri, 'pfe_sync_entry.tex');
                let existing, missing = false;
                try { existing = await vscode.workspace.fs.readFile(entryUri); }
                catch (error) { if (error.code !== 'FileNotFound') throw error; missing = true; }
                if (existing && !Buffer.from(existing).toString('utf8').startsWith(ENTRY_MARKER)) throw new Error('pfe_sync_entry.tex already exists and is not managed by this integration. It was not overwritten.');
                if (!existing || !canonicalContent('pfe_sync_entry.tex', existing).equals(content)) {
                    await writeRemoteContent({
                        read: () => vscode.workspace.fs.readFile(entryUri),
                        write: (name, bytes) => vscode.workspace.fs.writeFile(entryUri, bytes)
                    }, 'pfe_sync_entry.tex', content, missing);
                }
                filename = 'pfe_sync_entry.tex';
            }
            const entry = vfs.getValidMainDocs().find(item => item.path === '/' + filename);
            if (!entry) throw new Error(`The remote root entry ${filename} was not found after synchronization.`);
            if (!await vfs.updateSettings({ rootDocId: entry.entity._id })) throw new Error('Overleaf rejected the main-document setting.');
            output.appendLine(`Main document selected on Overleaf: /${filename}`);
            status.text = '$(sync~spin) Overleaf compiling';
            const compiled = await vfs.compile(true, false, true, entry.entity._id);
            output.appendLine(compiled ? 'PDF compilation: SUCCESS' : 'Sources synced and main document corrected; PDF compilation still failed. Check the new Overleaf log.');
            if (!compiled) vscode.window.showWarningMessage('Sources synchronized and the main-document path was corrected. Compilation still failed: open the new Overleaf log.');
        }
        function changed(file, deleted = false) {
            const relative = path.relative(source, file.fsPath).split(path.sep).join('/');
            if (!allowed(relative)) return;
            clearTimeout(pending.get(relative));
            pending.set(relative, setTimeout(() => {
                pending.delete(relative);
                current.enqueue(relative, deleted).catch(failure);
            }, 700));
        }
        watcher = vscode.workspace.createFileSystemWatcher(new vscode.RelativePattern(vscode.Uri.file(source), '**/*'));
        watcher.onDidCreate(file => changed(file));
        watcher.onDidChange(file => changed(file));
        watcher.onDidDelete(file => changed(file, true));
        status.text = '$(sync~spin) Overleaf uploading'; status.show();
        await current.uploadAll();
        if (current !== engine) return;
        await fixMainDocument();
        status.text = '$(cloud-upload) Overleaf auto sync';
        status.tooltip = `Local source: ${source}\nOne-way sync to Overleaf. Click to sync all files.`;
        output.appendLine('Initial synchronization finished. Watching external and editor changes.');
    }

    async function findRoot(folder) {
        const candidates = [];
        async function visit(uri, depth) {
            const entries = await vscode.workspace.fs.readDirectory(uri);
            const names = entries.map(([name]) => name);
            if (names.includes('main.tex') && names.includes('report.tex')) { candidates.push(uri); return; }
            if (depth === 0) return;
            for (const [name, type] of entries) {
                if ((type & vscode.FileType.Directory) && !name.startsWith('.')) await visit(vscode.Uri.joinPath(uri, name), depth - 1);
            }
        }
        await visit(folder.uri, 2);
        if (candidates.length === 1) return candidates[0];
        if (!candidates.length) throw new Error('The Overleaf project must already contain main.tex and report.tex. Upload the project ZIP first.');
        const selected = await vscode.window.showQuickPick(candidates.map(uri => ({ label: uri.path, uri })), { placeHolder: 'Select the remote LaTeX root containing main.tex and report.tex' });
        return selected?.uri;
    }

    context.subscriptions.push(output, status, { dispose: stop });
    context.subscriptions.push(vscode.commands.registerCommand('pfeOverleaf.start', async () => {
        try {
            const folder = vscode.workspace.workspaceFolders?.find(item => item.uri.scheme === 'overleaf-workshop');
            if (!folder) throw new Error('Open AES_SM4_DFA in a new window through Overleaf Workshop first, then run this command in that window.');
            const destination = await findRoot(folder);
            if (!destination) return;
            const localFolder = await vscode.window.showInputBox({ prompt: 'Local folder to mirror TO the currently open Overleaf project', value: vscode.workspace.getConfiguration('pfeOverleaf').get('localFolder') });
            if (!localFolder) return;
            const answer = await vscode.window.showWarningMessage(`Mirror ${localFolder} to ${folder.name}${destination.path}? Local files replace matching remote files; future local deletions are mirrored. Remote-only files stay in place.`, { modal: true }, 'Start automatic sync');
            if (answer !== 'Start automatic sync') return;
            const config = { localFolder, remoteUri: destination.toString() };
            await context.globalState.update('connection', config);
            await start(config);
            vscode.window.showInformationMessage('Automatic Overleaf sync is active. Keep this VS Code window open.');
        } catch (error) { failure(error); }
    }));
    context.subscriptions.push(vscode.commands.registerCommand('pfeOverleaf.stop', async () => {
        stop(); await context.globalState.update('connection', undefined);
    }));
    context.subscriptions.push(vscode.commands.registerCommand('pfeOverleaf.upload', async () => {
        try {
            if (!engine) throw new Error('Run PFE Overleaf: Connect and Start Automatic Sync first.');
            await engine.uploadAll();
            status.text = '$(cloud-upload) Overleaf auto sync';
        } catch (error) { failure(error); }
    }));
    const saved = context.globalState.get('connection');
    if (saved && vscode.workspace.workspaceFolders?.some(folder => folder.uri.scheme === 'overleaf-workshop' && folder.uri.query === vscode.Uri.parse(saved.remoteUri).query)) start(saved).catch(failure);
}

exports.activate = activate;
exports.allowed = allowed;
exports.localFiles = localFiles;
exports.createEngine = createEngine;
exports.writeRemoteContent = writeRemoteContent;
exports.canonicalContent = canonicalContent;
exports.entryDocument = entryDocument;
