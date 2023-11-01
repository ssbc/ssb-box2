// SPDX-FileCopyrightText: 2021 Anders Rune Jensen
//
// SPDX-License-Identifier: Unlicense

const { promisify } = require('util')
const test = require('tape')
const ssbKeys = require('ssb-keys')
const path = require('path')
const rimraf = require('rimraf')
const mkdirp = require('mkdirp')
const SecretStack = require('secret-stack')
const caps = require('ssb-caps')
const bfe = require('ssb-bfe')
const { DHKeys } = require('ssb-private-group-keys')
const pull = require('pull-stream')
const { keySchemes } = require('private-group-spec')

function readyDir(dir) {
  rimraf.sync(dir)
  mkdirp.sync(dir)
  return dir
}

const poBoxDH = new DHKeys().generate()

const poBoxId = bfe.decode(
  Buffer.concat([bfe.toTF('identity', 'po-box'), poBoxDH.toBuffer().public])
)
const testkey = poBoxDH.toBuffer().secret

let sbot
let keys

function setup() {
  const dir = readyDir('/tmp/ssb-db2-box2-tribes')
  keys = ssbKeys.loadOrCreateSync(path.join(dir, 'secret'))

  sbot = SecretStack({ appKey: caps.shs })
    .use(require('ssb-db2/core'))
    .use(require('ssb-classic'))
    .use(require('ssb-db2/compat/publish'))
    .use(require('ssb-db2/compat/post'))
    .use(require('../'))
    .call(null, {
      keys,
      path: dir,
      box2: {
        legacyMode: true,
      },
    })
}

function tearDown(cb) {
  if (cb === undefined) return promisify(tearDown)()

  sbot.close(true, cb)
}

test('pobox functions', async (t) => {
  setup()

  await sbot.box2.addPoBox(poBoxId, { key: testkey, scheme: keySchemes.po_box })

  const has = await sbot.box2.hasPoBox(poBoxId)

  t.equal(has, true, 'we have the pobox stored now')

  const poBoxInfo = await sbot.box2.getPoBox(poBoxId)

  t.deepEquals(
    poBoxInfo,
    {
      key: testkey,
      scheme: keySchemes.po_box,
    },
    'can get pobox info'
  )

  const listPoBoxIds = await pull(
    sbot.box2.listPoBoxIds(),
    pull.collectAsPromise()
  )
  t.deepEquals(listPoBoxIds, [poBoxId], 'can list the pobox')

  await tearDown()
})
