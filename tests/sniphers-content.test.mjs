import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const workspace = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
)
const dist = path.join(workspace, 'dist')
const categorySlug = '$n1phers-3-0-ctf'
const challenges = [
  ['sniphers-3-ctf-phantom-call', 'METAL GOT SOLID FLAGS: THE PHANTOM CALL'],
  ['sniphers-3-ctf-powershell', 'powershell'],
  ['sniphers-3-ctf-aes-slightly-illegal', 'AES… but make it slightly illegal'],
  ['sniphers-3-ctf-third-binder', 'Third Binder'],
  ['sniphers-3-ctf-dead-air-downlink', 'Dead-Air Downlink'],
  ['sniphers-3-ctf-alias-to-scene', 'Alias to Scene'],
  ['sniphers-3-ctf-our-times-passed-john', "Our Time's passed, John"],
  ['sniphers-3-ctf-blessed-heap-makers', 'Blessed are the Heap Makers'],
  ['sniphers-3-ctf-pingbox', 'PingBox'],
  ['sniphers-3-ctf-behind-the-gateway', 'Behind_the_gateway'],
]

function decodeNumericEntities(html) {
  return html.replace(/&#(\d+);/g, (_, codePoint) =>
    String.fromCodePoint(Number(codePoint)),
  )
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

test('publishes all $N1PH€RS 3.0 CTF challenges under the named category', () => {
  execFileSync('npm', ['run', 'build'], {
    cwd: workspace,
    stdio: 'pipe',
  })

  const categoryHtml = readFileSync(
    path.join(dist, 'categories', categorySlug, 'index.html'),
    'utf8',
  )
  const renderedCategory = decodeNumericEntities(categoryHtml)

  assert.match(renderedCategory, /\$N1PH€RS 3\.0 CTF/)

  for (const [slug, title] of challenges) {
    assert.ok(
      renderedCategory.includes(`href="/blog/${slug}"`),
      `missing category link for ${slug}`,
    )
    assert.ok(renderedCategory.includes(title), `missing title ${title}`)

    const renderedPost = decodeNumericEntities(
      readFileSync(path.join(dist, 'blog', slug, 'index.html'), 'utf8'),
    )
    assert.match(
      renderedPost,
      new RegExp(`<h1[^>]*>\\s*${escapeRegExp(title)}\\s*</h1>`),
    )
    assert.match(renderedPost, /<span>Abdieeuh<\/span>/)
  }

  const downlinkPost = decodeNumericEntities(
    readFileSync(
      path.join(dist, 'blog', 'sniphers-3-ctf-dead-air-downlink', 'index.html'),
      'utf8',
    ),
  )
  assert.match(
    downlinkPost,
    /href="\/static\/sniphers-3-ctf\/recovered_aztec\.png"/,
  )
  assert.ok(
    existsSync(
      path.join(dist, 'static', 'sniphers-3-ctf', 'recovered_aztec.png'),
    ),
    'the recovered Aztec image must be downloadable',
  )

  for (const slug of [
    'sniphers-3-ctf-dead-air-downlink',
    'sniphers-3-ctf-our-times-passed-john',
  ]) {
    const renderedPost = decodeNumericEntities(
      readFileSync(path.join(dist, 'blog', slug, 'index.html'), 'utf8'),
    )
    assert.doesNotMatch(renderedPost, /href="\.\/solve\.py"/)
  }
})
