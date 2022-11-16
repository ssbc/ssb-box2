// SPDX-FileCopyrightText: 2022 Mix Irving
//
// SPDX-License-Identifier: Unlicense

const SecretStack = require('secret-stack')
const ssbKeys = require('ssb-keys')
const bendyButtFormat = require('ssb-ebt/formats/bendy-butt')
const path = require('path')
const rimraf = require('rimraf')
const caps = require('ssb-caps')

let count = 0

module.exports = function createSbot(opts = {}) {
  const dir = opts.path || `/tmp/ssb-box2-tests-${opts.name || count++}`
  if (opts.rimraf !== false) rimraf.sync(dir)

  const keys = opts.keys || ssbKeys.loadOrCreateSync(path.join(dir, 'secret'))

  const stack = SecretStack({ appKey: caps.shs })
    .use(require('ssb-db2/core'))
    .use(require('ssb-classic'))
    .use(require('ssb-bendy-butt'))
    .use(require('ssb-db2/compat/feedstate'))
    .use(require('ssb-db2/compat/ebt'))
    .use(require('ssb-meta-feeds'))
    .use(require('../../'))
    .use(require('ssb-ebt'))

  const sbot = stack({
    path: dir,
    keys,
    ebt: {
      // logging: true,
    },
    metafeeds: {
      seed: opts.mfSeed,
    },
  })

  sbot.ebt.registerFormat(bendyButtFormat)

  return sbot
}
