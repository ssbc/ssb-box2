// SPDX-FileCopyrightText: 2022 Andre 'Staltz' Medeiros <contact@staltz.com>
//
// SPDX-License-Identifier: CC0-1.0

const test = require('tape')
const { promisify: p } = require('util')
const ssbKeys = require('ssb-keys')
const Testbot = require('./helpers/testbot')
const replicate = require('./helpers/replicate')

test('two chess subfeeds DM each other', async (t) => {
  const alice = Testbot({
    keys: ssbKeys.generate(null, 'alice'),
    mfSeed: Buffer.from(
      '000000000000000000000000000000000000000000000000000000000000a1ce',
      'hex'
    ),
  })
  const bob = Testbot({
    keys: ssbKeys.generate(null, 'bob'),
    mfSeed: Buffer.from(
      '0000000000000000000000000000000000000000000000000000000000000b0b',
      'hex'
    ),
  })

  const aliceRoot = await p(alice.metafeeds.findOrCreate)()
  const bobRoot = await p(bob.metafeeds.findOrCreate)()

  const aliceChess = await p(alice.metafeeds.findOrCreate)({ purpose: 'chess' })
  t.pass("alice's chess subfeed created")
  const bobChess = await p(bob.metafeeds.findOrCreate)({ purpose: 'chess' })
  t.pass("bob's chess subfeed created")

  await replicate(alice, bob)
  t.pass('alice and bob replicated')

  const msg = await p(alice.db.create)({
    keys: aliceChess.keys,
    content: { text: 'hello bob', type: 'post' },
    recps: [aliceRoot.id, bobRoot.id],
    encryptionFormat: 'box2',
  })
  t.pass('alice published an encrypted DB msg to bob')

  await replicate(alice, bob)
  t.pass('alice and bob replicated')

  const msgB = await p(bob.db.getMsg)(msg.key)
  t.equals(msgB.value.content.text, 'hello bob', 'bob sees the encrypted msg')

  await p(alice.close)(true)
  await p(bob.close)(true)
})

test('cannot use leaf feed as recp', async (t) => {
  const alice = Testbot({
    keys: ssbKeys.generate(null, 'alice'),
    mfSeed: Buffer.from(
      '000000000000000000000000000000000000000000000000000000000000a1ce',
      'hex'
    ),
  })
  const bob = Testbot({
    keys: ssbKeys.generate(null, 'bob'),
    mfSeed: Buffer.from(
      '0000000000000000000000000000000000000000000000000000000000000b0b',
      'hex'
    ),
  })

  const aliceRoot = await p(alice.metafeeds.findOrCreate)()
  const bobRoot = await p(bob.metafeeds.findOrCreate)()

  const aliceChess = await p(alice.metafeeds.findOrCreate)({ purpose: 'chess' })
  t.pass("alice's chess subfeed created")
  const bobChess = await p(bob.metafeeds.findOrCreate)({ purpose: 'chess' })
  t.pass("bob's chess subfeed created")

  await replicate(alice, bob)
  t.pass('alice and bob replicated')

  try {
    await p(alice.db.create)({
      keys: aliceChess.keys,
      content: { text: 'hello bob', type: 'post' },
      recps: [aliceRoot.id, bobChess.id],
      encryptionFormat: 'box2',
    })
    t.fail('alice should fail to encrypt this msg')
  } catch (err) {
    t.match(
      err.message,
      /create\(\) failed to encrypt content/,
      'error is correctly thrown when recp is wrong'
    )
  }

  await p(alice.close)(true)
  await p(bob.close)(true)
})
