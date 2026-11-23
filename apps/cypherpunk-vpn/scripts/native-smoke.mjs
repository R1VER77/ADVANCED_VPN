// Actual native WebKit/IPC-unavailable smoke. Run under xvfb-run + dbus-run-session.
// No mocked controller, host installation, hardware prompt or privileged action.
// Without the helper the first-launch agreement cannot be recorded, so the app must stay
// on it: the trial drives the agreement in real WebKit and requires that it fails closed.
import assert from 'node:assert/strict'
import { spawn, execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { createReadStream } from 'node:fs'
import { mkdir, writeFile, open } from 'node:fs/promises'
import net from 'node:net'
import path from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'

assert.notEqual(process.getuid(), 0, 'Run as an ordinary user')
const [binaryArgument, outputArgument] = process.argv.slice(2)
assert(binaryArgument && outputArgument, 'Usage: native-smoke.mjs NATIVE_BINARY NEW_OUTPUT_DIRECTORY')
const binary = path.resolve(binaryArgument)
const output = path.resolve(outputArgument)
// The native adapter deliberately fixes the real system-bus address. Refuse to
// exercise a machine with an active controller or an activatable production service.
const names = execFileSync('busctl', ['--system', 'call', 'org.freedesktop.DBus',
  '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'ListActivatableNames'], { encoding: 'utf8' })
assert(!names.includes('org.cypherpunk_vpn.Controller1'), 'Use a disposable host without the controller installed')
const owner = execFileSync('busctl', ['--system', 'call', 'org.freedesktop.DBus',
  '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'NameHasOwner', 's',
  'org.cypherpunk_vpn.Controller1'], { encoding: 'utf8' })
assert.equal(owner.trim(), 'b false', 'A live controller is outside this trial')
await mkdir(output, { mode: 0o700 })
const directories = ['runtime', 'config', 'cache', 'data']
for (const name of directories) await mkdir(path.join(output, name), { mode: 0o700 })
const server = net.createServer()
await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve) })
const port = server.address().port
await new Promise(resolve => server.close(resolve))
const environment = { ...process.env, GDK_BACKEND: 'x11', LIBGL_ALWAYS_SOFTWARE: '1',
  WEBKIT_DISABLE_COMPOSITING_MODE: '1', WEBKIT_INSPECTOR_HTTP_SERVER: `127.0.0.1:${port}`,
  XDG_RUNTIME_DIR: path.join(output, 'runtime'), XDG_CONFIG_HOME: path.join(output, 'config'),
  XDG_CACHE_HOME: path.join(output, 'cache'), XDG_DATA_HOME: path.join(output, 'data'),
  GTK_USE_PORTAL: '0', GSETTINGS_BACKEND: 'memory', GIO_USE_VFS: 'local' }
for (const key of ['SSH_AUTH_SOCK', 'GPG_AGENT_INFO', 'WEBKIT_INSPECTOR_SERVER']) delete environment[key]
const logfile = await open(path.join(output, 'native-app.log'), 'wx', 0o600)
const app = spawn(binary, [], { env: environment, stdio: ['ignore', logfile.fd, logfile.fd] })
const exited = new Promise(resolve => app.once('exit', resolve))
let client
const result = { schema: 1, status: 'running', scope: 'native_webkit_absent_controller_only',
  software_compositing: true, native_authentication_agent_qualified: false }

async function connect(endpoint) {
  const socket = new WebSocket(endpoint)
  let target, sequence = 0
  const waiting = new Map()
  let readyResolve, readyReject
  const ready = new Promise((resolve, reject) => { readyResolve = resolve; readyReject = reject })
  const timer = setTimeout(() => readyReject(new Error('Inspector page target unavailable')), 5000)
  function rejectAll(error) {
    readyReject(error)
    for (const entry of waiting.values()) entry.reject(error)
    waiting.clear()
  }
  socket.addEventListener('error', () => rejectAll(new Error('Inspector socket error')))
  socket.addEventListener('close', () => rejectAll(new Error('Inspector socket closed')))
  socket.addEventListener('message', event => {
    const message = JSON.parse(event.data)
    if (message.method === 'Target.targetCreated' && message.params.targetInfo.type === 'page') {
      target = message.params.targetInfo.targetId
      clearTimeout(timer)
      readyResolve()
    }
    if (message.method !== 'Target.dispatchMessageFromTarget') return
    const response = JSON.parse(message.params.message)
    const pending = waiting.get(response.id)
    if (!pending) return
    waiting.delete(response.id)
    if (response.error) pending.reject(new Error(JSON.stringify(response.error)))
    else pending.resolve(response.result)
  })
  try { await ready } catch (error) { socket.close(); throw error }
  async function request(method, params) {
    const id = ++sequence
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => { waiting.delete(id); reject(new Error('Inspector response timeout')) }, 5000)
      waiting.set(id, { resolve: value => { clearTimeout(timeout); resolve(value) },
        reject: error => { clearTimeout(timeout); reject(error) } })
      socket.send(JSON.stringify({ id: id + 100000, method: 'Target.sendMessageToTarget',
        params: { targetId: target, message: JSON.stringify({ id, method, params }) } }))
    })
  }
  return { close: () => socket.close(), async evaluate(expression) {
    const value = await request('Runtime.evaluate', { expression, returnByValue: true })
    assert(!value.wasThrown, 'Native page inspection threw')
    return JSON.parse(value.result.value)
  } }
}

const expression = `JSON.stringify({url:location.href,text:document.body.innerText,
  width:innerWidth,scroll:document.documentElement.scrollWidth,
  background:getComputedStyle(document.body).backgroundColor,
  passwordFields:document.querySelectorAll('input[type=password]').length,
  scripts:[...document.scripts].map(x=>x.src),styles:[...document.styleSheets].map(x=>x.href)})`
try {
  const deadline = Date.now() + 120000
  let snapshot
  while (Date.now() < deadline) {
    assert(app.exitCode === null && app.signalCode === null, 'Native app exited before readiness')
    try {
      if (!client) {
        const response = await fetch(`http://127.0.0.1:${port}/`, { signal: AbortSignal.timeout(1000) })
        assert(response.ok)
        const html = await response.text()
        assert(html.length < 65536 && html.includes('tauri://localhost'), 'Unexpected inspector target')
        const endpoint = html.match(/\/socket\/\d+\/\d+\/WebPage/)
        assert(endpoint, 'No native page target')
        client = await connect(`ws://127.0.0.1:${port}${endpoint[0]}`)
      }
      snapshot = await client.evaluate(expression)
      if (snapshot.text.includes('Understand the risks') && snapshot.background !== 'rgb(255, 255, 255)') break
    } catch { client?.close(); client = undefined }
    await delay(250)
  }
  assert(snapshot?.text.includes('Understand the risks'), 'Native frontend never showed the first-launch agreement')
  assert(!snapshot.text.includes('Connected') && !snapshot.text.includes('Status unknown'))
  assert.equal(snapshot.url, 'tauri://localhost')
  assert(snapshot.scripts.length > 0 && snapshot.styles.length > 0)
  assert([...snapshot.scripts, ...snapshot.styles].every(url => url.startsWith('tauri://localhost/')))
  assert.equal(snapshot.passwordFields, 0)
  const window = execFileSync('xdotool', ['search', '--onlyvisible', '--pid', String(app.pid),
    '--name', '^Cypherpunk VPN$'], { encoding: 'utf8' }).trim().split('\n')[0]
  assert(/^\d+$/.test(window))
  // A DOM-ready page may still be waiting for its first compositor paint.
  async function capture(name) {
    const file = path.join(output, name)
    for (let trial = 0; trial < 40; trial++) {
      execFileSync('import', ['-window', window, file])
      const colors = Number(execFileSync('identify', ['-format', '%k', file], { encoding: 'utf8' }))
      if (colors > 20) return
      await delay(250)
    }
    assert.fail('Native window remained blank after DOM readiness')
  }
  await capture('desktop.png')
  // Drive the agreement: Next stays disabled until both risks are acknowledged.
  const button = label => `[...document.querySelectorAll('button')].find(x => x.textContent.trim() === ${JSON.stringify(label)})`
  const before = await client.evaluate(`JSON.stringify({ next: ${button('Next')}?.disabled })`)
  assert.equal(before.next, true, 'Next must wait for both acknowledgements')
  const ticked = await client.evaluate(`(() => { const boxes = [...document.querySelectorAll('.check input')];
    boxes.forEach(x => { if (!x.checked) x.click() }); return JSON.stringify({ boxes: boxes.length }) })()`)
  assert.equal(ticked.boxes, 2)
  await delay(200)
  await client.evaluate(`(() => { ${button('Next')}.click(); return '{}' })()`)
  await delay(300)
  const terms = await client.evaluate(expression)
  for (const text of ['Terms and privacy', 'Terms of service', 'Privacy notice', 'Gemma Terms of Use',
    'Gemma Prohibited Use Policy', 'I have read and accept these terms']) assert(terms.text.includes(text), text)
  const acceptBefore = await client.evaluate(`JSON.stringify({ accept: ${button('Accept')}?.disabled })`)
  assert.equal(acceptBefore.accept, true, 'Accept must wait for its checkbox')
  await client.evaluate(`(() => { document.querySelector('.check input').click(); return '{}' })()`)
  await delay(200)
  await client.evaluate(`(() => { ${button('Accept')}.click(); return '{}' })()`)
  // No helper: acceptance cannot be recorded, so the app says so and stays on the agreement.
  let refused
  for (let trial = 0; trial < 40 && !refused?.text.includes('could not be saved'); trial++) {
    await delay(250)
    refused = await client.evaluate(expression)
  }
  assert(refused.text.includes('could not be saved'), 'An unrecorded acceptance must be refused visibly')
  assert(!refused.text.includes('Status unknown') && !refused.text.includes('Connected'), 'The app passed the agreement')
  execFileSync('xdotool', ['windowsize', window, '420', '640'])
  await delay(250)
  const narrow = await client.evaluate(expression)
  assert(narrow.width <= 420 && narrow.scroll <= narrow.width + 1, 'Narrow layout overflows')
  assert(narrow.text.includes('Terms and privacy') && narrow.passwordFields === 0)
  await capture('narrow.png')
  const hash = createHash('sha256')
  for await (const chunk of createReadStream(binary)) hash.update(chunk)
  Object.assign(result, { status: 'passed_native_agreement_gate', binary_sha256: hash.digest('hex'),
    embedded_assets_only: true, agreement_fails_closed_without_helper: true, narrow_without_horizontal_overflow: true })
} catch (error) {
  Object.assign(result, { status: 'failed', error: String(error) })
  process.exitCode = 1
} finally {
  client?.close()
  app.kill('SIGTERM')
  await Promise.race([exited, delay(5000)])
  if (app.exitCode === null && app.signalCode === null) { app.kill('SIGKILL'); await exited }
  await logfile.close()
  await writeFile(path.join(output, 'RESULT.json'), JSON.stringify(result, null, 2) + '\n', { flag: 'wx' })
  console.log(result.status)
}
