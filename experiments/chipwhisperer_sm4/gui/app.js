/* AES console visual structure, with SM4 word ordering and protocol. */
const $ = id => document.getElementById(id);
const VECTOR = '0123456789abcdeffedcba9876543210';
const CIPHERTEXT = '681edf34d206965e86b3e94f536e4246';
let connected = false;
let busy = false;

function log(message, cls = 'info') {
  const line = document.createElement('div');
  line.className = cls;
  line.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
  $('log').append(line);
  $('log').scrollTop = $('log').scrollHeight;
}

async function api(path, body) {
  const response = await fetch('/api/' + path, body === undefined ? {} : {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}

function controls() {
  for (const id of ['btnSetKey', 'btnEncrypt', 'btnDecrypt', 'btnFault']) {
    $(id).disabled = busy || !connected;
  }
  $('btnConnect').disabled = busy || connected;
  $('btnDisconnect').disabled = busy || !connected;
  for (const id of ['keyInput', 'encFill', 'decFill']) $(id).disabled = busy;
}

async function action(button, label, callback) {
  if (busy) return;
  busy = true;
  const original = button.textContent;
  button.textContent = label;
  controls();
  try { await callback(); }
  catch (error) { log(error.message, 'err'); }
  finally { busy = false; button.textContent = original; controls(); }
}

function setConnection(value) {
  connected = value;
  $('dot').classList.toggle('on', connected);
  $('statusText').textContent = connected ? 'Connected — SM4 revision 1 (fault-capable)' : 'Disconnected';
  controls();
}

function selectTab(name) {
  document.querySelectorAll('.tab').forEach(tab => tab.classList.toggle('active', tab.dataset.tab === name));
  document.querySelectorAll('.panel').forEach(panel => panel.classList.toggle('active', panel.id === 'panel-' + name));
}
document.querySelectorAll('.tab').forEach(tab => tab.addEventListener('click', () => selectTab(tab.dataset.tab)));

$('btnConnect').onclick = () => action($('btnConnect'), 'Connecting…', async () => {
  const result = await api('connect', {serial: $('serialNumber').value.trim()});
  setConnection(result.connected);
  $('keyInput').value = result.key;
  $('keyStatus').textContent = 'Known-answer encrypt/decrypt tests passed.';
  log('Connected to SM4 firmware. Encryption and decryption verified.');
});
$('btnDisconnect').onclick = () => action($('btnDisconnect'), 'Disconnecting…', async () => {
  await api('disconnect', {});
  setConnection(false);
  $('keyStatus').textContent = '';
  log('Disconnected.');
});
$('keyInput').oninput = () => { $('keyStatus').textContent = 'Edited key will be applied on the next operation.'; };
$('btnSetKey').onclick = () => action($('btnSetKey'), 'Setting key…', async () => {
  $('keyStatus').textContent = '';
  await api('key', {key: $('keyInput').value.trim()});
  $('keyStatus').textContent = 'Key set on target.';
  log('SM4 key updated.');
});
$('encFill').onclick = () => {
  $('encFormat').value = 'hex'; $('encValue').value = VECTOR; $('keyInput').value = VECTOR;
  $('keyInput').oninput();
};
$('decFill').onclick = () => {
  $('decValue').value = CIPHERTEXT; $('keyInput').value = VECTOR; $('decUnpad').checked = false;
  $('keyInput').oninput();
};

function element(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
}
function line(parent, label, value) {
  const row = element('div', 'hexline', label + ': ');
  row.append(element('b', '', String(value)));
  parent.append(row);
}
function delta(a, b) {
  return a.match(/../g).map((v, i) => (parseInt(v, 16) ^ parseInt(b.slice(i*2, i*2+2), 16)).toString(16).padStart(2, '0')).join('');
}
function distance(diff) {
  const values = diff.match(/../g).map(v => parseInt(v, 16));
  return `${values.filter(Boolean).length}/16 bytes, ${values.reduce((sum, v) => sum + v.toString(2).replace(/0/g, '').length, 0)}/128 bits differ`;
}
function matrix(hex, diff, fault = false) {
  const grid = element('div', 'grid4');
  // SM4: one word per row, big-endian bytes left to right (not AES columns).
  for (let i = 0; i < 16; i++) {
    const cell = element('div', 'cell', hex.slice(i*2, i*2+2));
    cell.title = `Word ${Math.floor(i/4)}, byte ${i%4} (0 = MSB)`;
    if (diff && diff.slice(i*2, i*2+2) !== '00') cell.classList.add(fault ? 'faultdiff' : 'diff');
    grid.append(cell);
  }
  return grid;
}

function stepper(parent, states, cleanStates = null, initial = 0) {
  if (!states.length) return;
  let index = initial;
  const row = element('div', 'stepper');
  const previous = element('button', '', '◀ prev');
  const next = element('button', '', 'next ▶');
  const info = element('span');
  const matrices = element('div', 'matrices');
  row.append(previous, info, next);
  parent.append(row, matrices);
  function draw() {
    const state = states[index];
    const diff = cleanStates ? delta(cleanStates[index].state, state.state) :
      index ? delta(states[index-1].state, state.state) : null;
    info.textContent = `Step ${index+1}/${states.length} — R${state.round} ${state.stage}` +
      (cleanStates ? ' — ' + distance(diff) : '');
    matrices.replaceChildren();
    function add(title, hex, highlight, faulty) {
      const box = element('div', 'matrix-block');
      box.append(element('h4', '', title), matrix(hex, highlight, faulty));
      matrices.append(box);
    }
    if (cleanStates) add('Correct state', cleanStates[index].state, null, false);
    add(cleanStates ? 'Faulty state' : 'State · rows W0–W3, bytes MSB → LSB', state.state, diff, !!cleanStates);
    previous.disabled = index === 0;
    next.disabled = index === states.length - 1;
  }
  previous.onclick = () => { index = Math.max(0, index-1); draw(); };
  next.onclick = () => { index = Math.min(states.length-1, index+1); draw(); };
  draw();
}

function render(data, container, faultRound = 0, padded = false) {
  const summary = element('div', 'card');
  summary.append(element('h2', '', 'Result'));
  const isFault = data.operation === 'fault';
  const isDecrypt = data.operation === 'decrypt';
  const clean = data.blocks.map(b => b.clean_output || b.output).join('');
  if (isFault) line(summary, 'Correct ciphertext', clean);
  line(summary, isDecrypt ? 'Plaintext (hex)' : isFault ? 'Faulty ciphertext' : 'Ciphertext', data.output);
  if (isFault) line(summary, 'Ciphertext XOR', delta(clean, data.output));
  if (isDecrypt) {
    line(summary, 'Plaintext (UTF-8, invalid bytes shown as replacement characters)', data.text);
    if (padded) summary.append(element('span', 'badge ok', 'PKCS#7 valid'));
  }
  summary.append(element('span', 'badge ok', 'target / Python verification passed'));
  const buttons = element('div', 'row');
  if (!isDecrypt) {
    const decrypt = element('button', '', 'Use ciphertext in Decrypt');
    decrypt.onclick = () => { $('decValue').value = data.output; $('decUnpad').checked = padded && !isFault; selectTab('decrypt'); };
    buttons.append(decrypt);
  }
  const download = element('button', '', 'Download result JSON');
  download.onclick = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'}));
    const anchor = element('a'); anchor.href = url; anchor.download = 'sm4-result.json'; anchor.click();
    URL.revokeObjectURL(url);
  };
  buttons.append(download); summary.append(buttons); container.append(summary);
  for (const block of data.blocks) {
    const card = element('div', 'block-card');
    line(card, `Block ${block.block}/${data.blocks.length} input`, block.input);
    line(card, 'Output', block.output);
    line(card, 'Inverse operation', block.recovered);
    card.append(element('span', 'badge ' + (block.roundtrip_ok ? 'ok' : 'bad'),
      block.roundtrip_ok ? 'round-trip OK' : 'different plaintext after injected fault'));
    if (block.fault_event) {
      line(card, 'Injected byte', block.fault_event.map(b => '0x' + b.toString(16).padStart(2, '0')).join(' → '));
      line(card, 'Changed ciphertext', `${block.changed_bytes} bytes / ${block.changed_bits} bits`);
    }
    stepper(card, block.snapshots, block.clean_snapshots, block.fault_event ? faultRound : 0);
    container.append(card);
  }
}

function run(operation, prefix, button, label) {
  return action($(button), label, async () => {
    const container = $(prefix + 'Results'); container.replaceChildren();
    const request = {operation, key: $('keyInput').value.trim(), value: $(prefix + 'Value').value,
      format: operation === 'decrypt' ? 'hex' : $(prefix + 'Format').value,
      trace: operation === 'encrypt' ? $('encTrace').checked : true,
      unpad: operation === 'decrypt' && $('decUnpad').checked};
    if (operation === 'fault') {
      const mask = $('fltMask').value.trim();
      if (!/^(?:0x)?[0-9a-f]{1,2}$/i.test(mask)) throw Error('XOR mask must be 01..ff, optionally prefixed with 0x.');
      request.fault = [Number($('fltRound').value), Number($('fltWord').value), Number($('fltByte').value), parseInt(mask, 16)];
      request.block = Number($('fltBlock').value);
    }
    const data = await api('run', request);
    $('keyStatus').textContent = 'Key set on target.';
    render(data, container, request.fault?.[0] || 0, operation === 'decrypt' ? request.unpad : request.format === 'text');
    log(`${operation}: ${data.blocks.length} block(s) verified. Output: ${data.output}`);
  });
}
$('btnEncrypt').onclick = () => run('encrypt', 'enc', 'btnEncrypt', 'Encrypting…');
$('btnDecrypt').onclick = () => run('decrypt', 'dec', 'btnDecrypt', 'Decrypting…');
$('btnFault').onclick = () => run('fault', 'flt', 'btnFault', 'Injecting…');
controls();
api('status').then(state => { setConnection(state.connected); if (state.key) $('keyInput').value = state.key; }).catch(error => log(error.message, 'err'));
