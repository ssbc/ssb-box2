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
const pull = require('pull-stream')
const bendyButt = require('ssb-bendy-butt')
const SSBURI = require('ssb-uri2')

const { and, or, where, author, type, toPullStream } = require('ssb-db2/operators')

const dir = '/tmp/ssb-db2-box2'

rimraf.sync(dir)
mkdirp.sync(dir)

const keys = ssbKeys.loadOrCreateSync(path.join(dir, 'secret'))

const sbot = SecretStack({ appKey: caps.shs })
 .use(require('ssb-db2'))
 .use(require('../'))
 .call(null, {
   keys,
   path: dir,
 })
const db = sbot.db

test('db.add bendy butt', (t) => {
  const testkey = Buffer.from(
    '30720d8f9cbf37f6d7062826f6decac93e308060a8aaaa77e6a4747f40ee1a76',
    'hex'
  )

  sbot.box2.addOwnDMKey(testkey)
  sbot.box2.setReady()

  // fake some keys
  const mfKeys = ssbKeys.generate()
  const classicUri = SSBURI.fromFeedSigil(mfKeys.id)
  const { type, /* format, */ data } = SSBURI.decompose(classicUri)
  const bendybuttUri = SSBURI.compose({ type, format: 'bendybutt-v1', data })
  mfKeys.id = bendybuttUri

  const mainKeys = ssbKeys.generate()

  const content = {
    type: "metafeed/add",
    feedpurpose: "secret purpose",
    subfeed: mainKeys.id,
    metafeed: mfKeys.id,
    recps: [keys.id],
    tangles: {
      metafeed: {
        root: null,
        previous: null
      }
    }
  }

  const bbmsg = bendyButt.encodeNew(
    content,
    mainKeys,
    mfKeys,
    1,
    null,
    Date.now(),
    null,
    sbot.box2.encryptBendyButt
  )

  const msgVal = bendyButt.decode(bbmsg)
  
  db.add(msgVal, (err, privateMsg) => {
    t.error(err, 'no err')

    t.true(privateMsg.value.content.endsWith(".box2"), 'box2 encoded')
    db.get(privateMsg.key, (err, msg) => {
      t.error(err, 'no err')
      t.equal(msg.content.feedpurpose, 'secret purpose')
      sbot.close(t.end)
    })
  })
})

test('box2', (t) => {
  const testkey = Buffer.from(
    '30720d8f9cbf37f6d7062826f6decac93e308060a8aaaa77e6a4747f40ee1a76',
    'hex'
  )

  const dirBox2 = '/tmp/ssb-db2-private-box2'
  rimraf.sync(dirBox2)
  mkdirp.sync(dirBox2)

  const sbotBox2 = SecretStack({ appKey: caps.shs })
    .use(require('ssb-db2'))
    .use(require('../'))
    .call(null, {
      keys,
      path: dirBox2,
      box2: {
        alwaysbox2: true
      }
    })

  sbotBox2.box2.addOwnDMKey(testkey)
  sbotBox2.box2.setReady()

  let content = { type: 'post', text: 'super secret', recps: [keys.id] }

  sbotBox2.db.publish(content, (err, privateMsg) => {
    t.error(err, 'no err')

    t.true(privateMsg.value.content.endsWith(".box2"), 'box2 encoded')
    sbotBox2.db.get(privateMsg.key, (err, msg) => {
      t.error(err, 'no err')
      t.equal(msg.content.text, 'super secret')

      // encrypt to another key

      const dirKeys2 = '/tmp/ssb-db2-private-box2-2'
      rimraf.sync(dirKeys2)
      mkdirp.sync(dirKeys2)

      const keys2 = ssbKeys.loadOrCreateSync(path.join(dirKeys2, 'secret'))

      const sbotKeys2 = SecretStack({ appKey: caps.shs })
        .use(require('ssb-db2'))
        .use(require('../'))
        .call(null, {
          keys: keys2,
          path: dirKeys2,
          box2: {
            alwaysbox2: true
          }
        })

      sbotKeys2.box2.setReady()

      let contentKeys2 = { type: 'post', text: 'keys2 secret', recps: [keys2.id] }

      sbotBox2.db.publish(contentKeys2, (err, privateKeys2Msg) => {
        sbotKeys2.db.add(privateMsg.value, (err) => {
          sbotKeys2.db.add(privateKeys2Msg.value, (err) => {
            t.error(err, 'no err')
            sbotKeys2.db.get(privateKeys2Msg.key, (err, msg) => {
              t.error(err, 'no err')
              t.equal(msg.content.text, 'keys2 secret')

              sbotKeys2.db.get(privateMsg.key, (err, msg) => {
                t.error(err, 'no err')
                t.true(privateMsg.value.content.endsWith(".box2"), 'box2 encoded')

                sbotBox2.close(() => sbotKeys2.close(t.end))
              })
            })
          })
        })
      })
    })
  })
})

test('box2 group', (t) => {
  const groupKey = Buffer.from(
    '30720d8f9cbf37f6d7062826f6decac93e308060a8aaaa77e6a4747f40ee1a76',
    'hex'
  )
  const groupId = 'group1.8K-group'

  const dirBox2 = '/tmp/ssb-db2-private-box2-group'
  rimraf.sync(dirBox2)
  mkdirp.sync(dirBox2)

  const sbotBox2 = SecretStack({ appKey: caps.shs })
    .use(require('ssb-db2'))
    .use(require('../'))
    .call(null, {
      keys,
      path: dirBox2,
      box2: {
        alwaysbox2: true
      }
    })

  sbotBox2.box2.addGroupKey(groupId, groupKey)
  sbotBox2.box2.registerIsGroup((recp) => recp.endsWith('8K-group'))
  sbotBox2.box2.setReady()

  let content = { type: 'post', text: 'super secret', recps: [groupId] }

  sbotBox2.db.publish(content, (err, privateMsg) => {
    t.error(err, 'no err')

    t.true(privateMsg.value.content.endsWith(".box2"), 'box2 encoded')
    sbotBox2.db.get(privateMsg.key, (err, msg) => {
      t.error(err, 'no err')
      t.equal(msg.content.text, 'super secret')
      sbotBox2.close(t.end)
    })
  })
})

test('box2 group reindex', (t) => {
  const groupKey = Buffer.from(
    '30720d8f9cbf37f6d7062826f6decac93e308060a8aaaa77e6a4747f40ee1a76',
    'hex'
  )

  const groupId = 'group1.8K-group'

  const dirAlice = '/tmp/ssb-db2-box2-group-reindex-alice'
  rimraf.sync(dirAlice)
  mkdirp.sync(dirAlice)

  const keysAlice = ssbKeys.loadOrCreateSync(path.join(dirAlice, 'secret'))

  const alice = SecretStack({ appKey: caps.shs })
    .use(require('ssb-db2'))
    .use(require('../'))
    .call(null, {
      keys: keysAlice,
      path: dirAlice,
      box2: {
        alwaysbox2: true
      }
    })

  alice.box2.addGroupKey(groupId, groupKey)
  alice.box2.registerIsGroup((recp) => recp.endsWith('8K-group'))
  alice.box2.setReady()

  const dirBob = '/tmp/ssb-db2-box2-group-reindex-bob'
  rimraf.sync(dirBob)
  mkdirp.sync(dirBob)

  const keysBob = ssbKeys.loadOrCreateSync(path.join(dirBob, 'secret'))

  const bob = SecretStack({ appKey: caps.shs })
    .use(require('ssb-db2'))
    .use(require('../'))
    .call(null, {
      keys: keysBob,
      path: dirBob,
      box2: {
        alwaysbox2: true
      }
    })

  bob.box2.registerIsGroup((recp) => recp.endsWith('8K-group'))
  bob.box2.setReady()
  
  let content = { type: 'post', text: 'super secret', recps: [groupId] }

  alice.db.publish(content, (err, privateMsg) => {
    t.error(err, 'no err')

    t.true(privateMsg.value.content.endsWith(".box2"), 'box2 encoded')

    bob.db.add(privateMsg.value, (err, m) => {
      pull(
        bob.db.query(
          // we use or here because we would like to have the type
          // index created even if we don't use it to make sure
          // reindexing works properly
          where(or(author(alice.id), type('post'))),
          toPullStream()
        ),
        pull.collect((err, msgs) => {
          const msg = msgs[0]
          t.true(msg.value.content.endsWith(".box2"), 'box2 encoded')

          bob.box2.addGroupKey(groupId, groupKey)

          bob.db.reindexEncrypted(() => {
            pull(
              bob.db.query(
                where(and(author(alice.id), type('post'))),
                toPullStream()
              ),
              pull.collect((err, msgs) => {
                const msg = msgs[0]
                t.equal(msg.value.content.text, 'super secret')

                bob.close(() => alice.close(t.end))
              })
            )
          })
        })
      )
    })
  })
})
