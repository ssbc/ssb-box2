// SPDX-FileCopyrightText: 2021 Anders Rune Jensen
//
// SPDX-License-Identifier: Unlicense

const test = require('tape')
const ssbKeys = require('ssb-keys')
const path = require('path')
const rimraf = require('rimraf')
const mkdirp = require('mkdirp')
const SecretStack = require('secret-stack')
const caps = require('ssb-caps')
const ref = require('ssb-ref')
const pull = require('pull-stream')

function readyDir(dir) {
  rimraf.sync(dir)
  mkdirp.sync(dir)
  return dir
}

const groupId = '%Lihvp+fMdt5CihjbOY6eZc0qCe0eKsrN2wfgXV2E3PM=.cloaked'

let sbot
let keys
let db1Keys
let db1Sbot

test('setup', (t) => {
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

  const db1Dir = readyDir('/tmp/ssb-db2-box2-tribes-db1')
  db1Keys = ssbKeys.loadOrCreateSync(path.join(db1Dir, 'secret2'))

  db1Sbot = SecretStack({ caps })
    .use(require('ssb-db'))
    .use(require('ssb-backlinks'))
    .use(require('ssb-query'))
    .use(require('ssb-tribes'))
    .call(null, {
      keys: db1Keys,
      path: db1Dir,
    })

  t.end()
})

test('DM message can be read with tribes1', (t) => {
  const testkey = Buffer.from(
    '30720d8f9cbf37f6d7062826f6decac93e308060a8aaaa77e6a4747f40ee1a76',
    'hex'
  )

  sbot.box2.setOwnDMKey(testkey)

  const opts = {
    keys,
    content: { type: 'post', text: 'super secret' },
    encryptionFormat: 'box2',
    recps: [keys.id, db1Keys.id],
  }

  sbot.db.create(opts, (err, privateMsg) => {
    t.error(err, 'no err')

    t.equal(typeof privateMsg.value.content, 'string')
    sbot.db.get(privateMsg.key, (err, msg) => {
      t.equal(msg.content.text, 'super secret')

      db1Sbot.add(privateMsg.value, (err) => {
        db1Sbot.get({ id: privateMsg.key, private: true }, (err, db1Msg) => {
          t.equal(db1Msg.content.text, 'super secret')
          t.end()
        })
      })
    })
  })
})

test('second DM message can be read with tribes1', (t) => {
  const opts = {
    keys,
    content: { type: 'post', text: 'super secret 2' },
    recps: [keys.id, db1Keys.id],
    encryptionFormat: 'box2',
  }

  sbot.db.create(opts, (err, privateMsg) => {
    t.error(err, 'no err')

    t.equal(typeof privateMsg.value.content, 'string')
    sbot.db.get(privateMsg.key, (err, msg) => {
      t.equal(msg.content.text, 'super secret 2')

      db1Sbot.add(privateMsg.value, (err) => {
        db1Sbot.get({ id: privateMsg.key, private: true }, (err, db1Msg) => {
          t.equal(db1Msg.content.text, 'super secret 2')
          t.end()
        })
      })
    })
  })
})

test('group message can be read with tribes1', (t) => {
  const testkey = Buffer.from(
    '50720d8f9cbf37f6d7062826f6decac93e308060a8aaaa77e6a4747f40ee1a76',
    'hex'
  )

  const registerOpts = {
    key: testkey.toString('base64'),
    root: '%MPB9vxHO0pvi2ve2wh6Do05ZrV7P6ZjUQ+IEYnzLfTs=.sha256',
  }

  sbot.box2.addGroupInfo(groupId, { key: testkey, root: registerOpts.root })

  db1Sbot.tribes.register(groupId, registerOpts, (err) => {
    db1Sbot.tribes.registerAuthors(groupId, [keys.id, db1Keys.id], (err) => {
      const opts = {
        keys,
        content: { type: 'post', text: 'super secret' },
        encryptionFormat: 'box2',
        recps: [groupId],
      }

      sbot.db.create(opts, (err, privateMsg) => {
        t.error(err, 'no err')

        t.equal(typeof privateMsg.value.content, 'string')
        sbot.db.get(privateMsg.key, (err, msg) => {
          t.equal(msg.content.text, 'super secret')

          db1Sbot.add(privateMsg.value, (err) => {
            db1Sbot.get(
              { id: privateMsg.key, private: true },
              (err, db1Msg) => {
                t.equal(db1Msg.content.text, 'super secret')
                t.end()
              }
            )
          })
        })
      })
    })
  })
})

test('we can decrypt a message created with tribes1', (t) => {
  let content = {
    type: 'post',
    text: 'super secret 3',
    recps: [keys.id, db1Keys.id],
  }

  db1Sbot.publish(content, (err, privateMsg) => {
    t.error(err, 'no err')

    t.equal(typeof privateMsg.value.content, 'string')
    sbot.db.add(privateMsg.value, (err) => {
      sbot.db.get(privateMsg.key, (err, db2Msg) => {
        t.equal(db2Msg.content.text, 'super secret 3')
        t.end()
      })
    })
  })
})

test('we can decrypt a second message created with tribes1', (t) => {
  let content = {
    type: 'post',
    text: 'super secret 4',
    recps: [keys.id, db1Keys.id],
  }

  db1Sbot.publish(content, (err, privateMsg) => {
    t.error(err, 'no err')

    t.equal(typeof privateMsg.value.content, 'string')
    sbot.db.add(privateMsg.value, (err) => {
      sbot.db.get(privateMsg.key, (err, db2Msg) => {
        t.equal(db2Msg.content.text, 'super secret 4')
        t.end()
      })
    })
  })
})

test('we can decrypt a group message created with tribes1', (t) => {
  // group already registered

  let content = {
    type: 'post',
    text: 'super secret 3',
    recps: [groupId],
  }

  db1Sbot.publish(content, (err, privateMsg) => {
    t.error(err, 'no err')

    t.equal(typeof privateMsg.value.content, 'string')
    sbot.db.add(privateMsg.value, (err) => {
      sbot.db.get(privateMsg.key, (err, db2Msg) => {
        t.equal(db2Msg.content.text, 'super secret 3')
        t.end()
      })
    })
  })
})

test('can list group ids', (t) => {
  pull(
    sbot.box2.listGroupIds(),
    pull.collect((err, ids) => {
      if (err) t.fail(err)

      t.equal(ids.length, 1, 'lists the one group we are in')

      t.true(
        ref.isCloakedMsg(ids[0]),
        'lists a group id and not something else'
      )

      t.end()
    })
  )
})

test('can list group ids live', (t) => {
  pull(
    sbot.box2.listGroupIds({ live: true }),
    pull.take(1),
    pull.collect((err, ids) => {
      if (err) t.fail(err)

      t.equal(ids.length, 1, 'lists the one group we are in')

      t.true(
        ref.isCloakedMsg(ids[0]),
        'lists a group id and not something else'
      )

      t.end()
    })
  )
})

test('can get group info', async (t) => {
  const info = await sbot.box2.getGroupKeyInfo(groupId)

  t.true(Buffer.isBuffer(info.key), 'key is a buffer')
  t.equal(info.scheme, 'envelope-large-symmetric-group', 'scheme is correct')
  t.true(ref.isMsg(info.root), 'has root')

  t.end()
})

test('teardown', (t) => {
  sbot.close(() => db1Sbot.close(t.end))
})
