// Test the actual overridden dependency and a disposable guard-removed mutant.
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createRequire } from 'node:module'
import { spawnSync } from 'node:child_process'

const require = createRequire(import.meta.url)
const picomatch = require('picomatch')
const metadata = require('picomatch/package.json')
assert.equal(metadata.name, '@cypherpunk-vpn/picomatch-build-guard')
const denied = ['+(*)', '+(*a)b', '*(*a)b', 'src/+(*a)b', '+(@(a))', '+(a|b)', String.raw`\+(a)`, '"*(a)"']
for (const pattern of denied) {
  for (const options of [{}, { fastpaths: true }, { maxExtglobRecursion: false }, { noext: true }]) {
    assert.throws(() => picomatch.makeRe(pattern, options), /Repeated extglobs are disabled/)
    assert.throws(() => picomatch.parse(pattern, options), /Repeated extglobs are disabled/)
  }
}
const match = picomatch('**/*.{vue,ts}')
assert.equal(match('src/App.vue'), true)
assert.equal(match('src/controller/types.ts'), true)
assert.equal(match('src/style.css'), false)
assert.equal(picomatch('src/**/!(*.test).ts')('src/controller/types.ts'), true)

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'cypherpunk-glob-mutant-'))
try {
  const source = path.resolve(import.meta.dirname, '../vendor/picomatch')
  const mutant = path.join(temporary, 'picomatch')
  fs.cpSync(source, mutant, { recursive: true })
  const parser = path.join(mutant, 'lib/parse.js')
  const before = fs.readFileSync(parser, 'utf8')
  assert.equal(before.split('rejectRepeatedExtglobs(input);').length - 1, 2)
  fs.writeFileSync(parser, before.replaceAll('rejectRepeatedExtglobs(input);', ''))
  // Bound the vulnerable counterexample in its own disposable process. The
  // parent never runs the unsafe expression or waits without a deadline.
  const code = `const pm=require(${JSON.stringify(mutant)});pm('+(*a)b')('a'.repeat(40)+'c')`
  const trial = spawnSync(process.execPath, ['--max-old-space-size=64', '-e', code], { timeout: 1000 })
  assert.equal(trial.error?.code, 'ETIMEDOUT', 'guard-removed counterexample did not reproduce the vulnerability')
} finally {
  fs.rmSync(temporary, { recursive: true, force: true })
}
console.log('GLOB_GUARD_PASS: repeated extglobs refused; supported globs work; guard-removed mutant times out')
