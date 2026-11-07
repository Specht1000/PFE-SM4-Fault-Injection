const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { allowed, localFiles, createEngine, writeRemoteContent, canonicalContent, entryDocument } = require('./extension');

test('nested Overleaf projects get a root entry and correct input search path', () => {
    const entry = entryDocument('overleaf_project');
    assert.ok(entry.startsWith('% Managed by PFE Overleaf Auto Sync'));
    assert.ok(entry.includes('\\def\\input@path{{overleaf_project/}}'));
    assert.ok(entry.includes('\\input{overleaf_project/main.tex}'));
    assert.ok(entryDocument('overleaf_project', 'part_04.tex').includes('\\input{overleaf_project/part_04.tex}'));
    assert.throws(() => entryDocument('../outside'));
    assert.throws(() => entryDocument('x% malicious'));
    assert.throws(() => entryDocument('folder', '../main.tex'));
});

test('Windows text and Overleaf text have the same canonical representation', () => {
    assert.equal(canonicalContent('main.tex', Buffer.from('\uFEFFone\r\ntwo\r\n')).toString(), 'one\ntwo\n');
    assert.equal(canonicalContent('main.tex', Buffer.from('one\ntwo\n')).toString(), 'one\ntwo\n');
    const binary = Buffer.from([255, 13, 10, 0]);
    assert.deepEqual(canonicalContent('logo.png', binary), binary);
});

test('verification waits for remote events without uploading twice', async () => {
    const folder = await fs.mkdtemp(path.join(os.tmpdir(), 'pfe-sync-'));
    try {
        await fs.writeFile(path.join(folder, 'main.tex'), 'new\r\ntext\r\n');
        let writes = 0, reads = 0;
        const engine = createEngine(folder, {
            async read() { reads++; return Buffer.from(reads < 4 ? 'old\n' : 'new\ntext\n'); },
            async write(name, data) { writes++; assert.equal(data.toString(), 'new\ntext\n'); },
            async remove() {}
        }, () => {}, async () => {});
        await engine.enqueue('main.tex');
        assert.equal(writes, 1);
        assert.equal(reads, 4);
    } finally { await removeTestFolder(folder); }
});

test('normalization never conceals a real content mismatch', async () => {
    const folder = await fs.mkdtemp(path.join(os.tmpdir(), 'pfe-sync-'));
    try {
        await fs.writeFile(path.join(folder, 'main.tex'), 'correct\r\n');
        const engine = createEngine(folder, {
            async read() { return Buffer.from('wrong\n'); },
            async write() {}, async remove() {}
        }, () => {}, async () => {});
        await assert.rejects(engine.enqueue('main.tex'), /first difference at byte 0/);
    } finally { await removeTestFolder(folder); }
});

async function removeTestFolder(folder) {
    assert.equal(path.dirname(path.resolve(folder)), path.resolve(os.tmpdir()));
    assert.ok(path.basename(folder).startsWith('pfe-sync-'));
    await fs.rm(folder, { recursive: true, force: true });
}

test('only project sources and assets are synchronized', () => {
    for (const name of ['main.tex', 'chapters/aes.tex', 'logo.png', 'references.bib']) assert.equal(allowed(name), true);
    for (const name of ['../secret.tex', '.git/config', '.overleaf/settings.json', 'overleaf_project.zip', 'output.pdf', 'main.aux', 'main.log', 'x.py']) assert.equal(allowed(name), false);
});

test('new text documents avoid the rejected multipart upload route', async () => {
    const files = new Map();
    const calls = [];
    const remote = {
        async read(name) { calls.push(`read:${name}`); return files.get(name); },
        async write(name, content) {
            if (!files.has(name) && content.length > 0) throw new Error('400 invalid_upload_request');
            calls.push(`write:${name}:${content.length}`);
            files.set(name, Buffer.from(content));
        }
    };
    for (const name of ['main.tex', 'report.tex', 'OVERLEAF.md']) {
        await writeRemoteContent(remote, name, Buffer.from('New text'), true);
        assert.equal(files.get(name).toString(), 'New text');
        assert.deepEqual(calls.splice(0), [`write:${name}:0`, `read:${name}`, `write:${name}:8`]);
        await writeRemoteContent(remote, name, Buffer.from('Edited'), false);
        assert.deepEqual(calls.splice(0), [`write:${name}:6`]);
    }
});

test('disk edits, new files, deletion and initial source inventory', async () => {
    const folder = await fs.mkdtemp(path.join(os.tmpdir(), 'pfe-sync-'));
    try {
        const stored = new Map([['remote-only.tex', Buffer.from('Keep')]]);
        const messages = [];
        const remote = {
            async read(name) { if (!stored.has(name)) throw Object.assign(new Error('Missing'), { code: 'FileNotFound' }); return stored.get(name); },
            async write(name, data) { stored.set(name, Buffer.from(data)); },
            async remove(name) { stored.delete(name); }
        };
        const engine = createEngine(folder, remote, message => messages.push(message));
        await fs.mkdir(path.join(folder, 'chapters'));
        await fs.writeFile(path.join(folder, 'main.tex'), 'Initial');
        await fs.writeFile(path.join(folder, 'chapters', 'aes.tex'), 'AES');
        await fs.writeFile(path.join(folder, 'project.zip'), 'Ignored');
        assert.deepEqual(await localFiles(folder), ['chapters/aes.tex', 'main.tex']);
        await engine.uploadAll();
        assert.equal(stored.get('main.tex').toString(), 'Initial');
        await fs.writeFile(path.join(folder, 'main.tex'), 'Changed by external editor');
        await engine.enqueue('main.tex');
        assert.equal(stored.get('main.tex').toString(), 'Changed by external editor');
        const count = messages.length;
        await engine.enqueue('main.tex');
        assert.equal(messages.length, count, 'Unchanged files must not be uploaded again');
        await fs.unlink(path.join(folder, 'chapters', 'aes.tex'));
        await engine.enqueue('chapters/aes.tex', true);
        assert.equal(stored.has('chapters/aes.tex'), false);
        assert.equal(stored.get('remote-only.tex').toString(), 'Keep');
        engine.stop();
        await fs.writeFile(path.join(folder, 'main.tex'), 'Do not upload');
        await engine.enqueue('main.tex');
        assert.equal(stored.get('main.tex').toString(), 'Changed by external editor');
    } finally { await removeTestFolder(folder); }
});

test('network errors are surfaced and later synchronization can retry', async () => {
    const folder = await fs.mkdtemp(path.join(os.tmpdir(), 'pfe-sync-'));
    try {
        await fs.writeFile(path.join(folder, 'main.tex'), 'Content');
        let fail = true;
        let stored;
        const engine = createEngine(folder, {
            async read() { if (fail) throw Object.assign(new Error('Offline'), { code: 'Unavailable' }); return stored; },
            async write(name, data) { stored = Buffer.from(data); },
            async remove() {}
        }, () => {});
        await assert.rejects(engine.enqueue('main.tex'), /Offline/);
        fail = false;
        await engine.enqueue('main.tex');
        assert.equal(stored.toString(), 'Content');
    } finally { await removeTestFolder(folder); }
});
