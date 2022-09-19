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

function readyDir(dir) {
  rimraf.sync(dir)
  mkdirp.sync(dir)
  return dir
}

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
    .use(require('ssb-box'))
    .use(require('ssb-db2/compat/publish'))
    .use(require('ssb-db2/compat/post'))
    .use(require('../'))
    .call(null, {
      keys,
      path: dir,
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

test('box2 message can be read with tribes', (t) => {
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

test('second box2 message can be read with tribes', (t) => {
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

test('box2 group message can be read with tribes', (t) => {
  const testkey = Buffer.from(
    '50720d8f9cbf37f6d7062826f6decac93e308060a8aaaa77e6a4747f40ee1a76',
    'hex'
  )

  const groupId = '%Lihvp+fMdt5CihjbOY6eZc0qCe0eKsrN2wfgXV2E3PM=.cloaked'
  sbot.box2.addGroupKey(groupId, testkey)

  const registerOpts = {
    key: testkey.toString('base64'),
    root: '%MPB9vxHO0pvi2ve2wh6Do05ZrV7P6ZjUQ+IEYnzLfTs=.sha256'
  }

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
            db1Sbot.get({ id: privateMsg.key, private: true }, (err, db1Msg) => {
              t.equal(db1Msg.content.text, 'super secret')
              t.end()
            })
          })
        })
      })
    })
  })
})

test('we can decrypt a message created with tribes', (t) => {
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

test('we can decrypt a second message created with tribes', (t) => {
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

test('we can decrypt a group message created with tribes', (t) => {
  // group already registered
  const groupId = '%Lihvp+fMdt5CihjbOY6eZc0qCe0eKsrN2wfgXV2E3PM=.cloaked'

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

test('can list group keys', (t) => {
  sbot.box2.listGroupKeys().then(keys=> {
    t.equal(keys.length, 1)

    t.end()
  })
    .catch(t.error)
})

test('teardown', (t) => {
  sbot.close(() => db1Sbot.close(t.end))
})
