// SPDX-FileCopyrightText: 2022 Andre 'Staltz' Medeiros
//
// SPDX-License-Identifier: LGPL-3.0-only

const { promisify } = require('util')
const BFE = require('ssb-bfe')
const Ref = require('ssb-ref')
const Uri = require('ssb-uri2')
const path = require('path')
const os = require('os')
const { box, unbox } = require('envelope-js')
const { SecretKey } = require('ssb-private-group-keys')
const Keyring = require('ssb-keyring')
const { ReadyGate } = require('./utils')

function reportError(err) {
  if (err) console.error(err)
}

const ATTEMPT1 = { maxAttempts: 1 }
const ATTEMPT16 = { maxAttempts: 16 }

function makeEncryptionFormat() {
  let _keyring = null
  const _keyringReady = new ReadyGate()

  function setup(config, cb) {
    const keyringPath = path.join(
      config.path || path.join(os.tmpdir(), '.ssb-keyring-' + Date.now()),
      'keyring'
    )
    Keyring(keyringPath, (err, api) => {
      if (err) return cb(err)
      _keyring = api
      _keyring.dm.addFromSSBKeys(config.keys)
      _keyringReady.setReady()
      cb()
    })
  }

  function teardown(cb) {
    _keyringReady.onReady(() => {
      _keyring.close(cb)
    })
  }

  function _isGroup(recp) {
    return _keyring.group.has(recp)
  }

  function _isFeed(recp) {
    return (
      Ref.isFeed(recp) ||
      Uri.isClassicFeedSSBURI(recp) ||
      Uri.isBendyButtV1FeedSSBURI(recp) ||
      Uri.isButtwooV1FeedSSBURI(recp)
    )
  }

  function setOwnDMKey(key) {
    _keyringReady.onReady(() => {
      _keyring.self.set({ key }, reportError)
    })
  }

  //TODO: update docs
  function addGroupInfo(id, info) {
    _keyringReady.onReady(() => {
      _keyring.group.add(id, info, reportError)
    })
  }

  function listGroupIds(cb) {
    if (cb === undefined) return promisify(listGroupIds)()

    _keyringReady.onReady(() => {
      cb(null, _keyring.group.list())
    })
  }

  function addKeypair(keypair) {
    _keyringReady.onReady(() => {
      _keyring.dm.addFromSSBKeys(keypair)
    })
  }

  function encrypt(plaintextBuf, opts) {
    const recps = opts.recps
    const authorId = opts.keys.id
    const previousId = opts.previous

    const validRecps = recps
      .filter((recp) => typeof recp === 'string')
      .filter((recp) => recp === authorId || _isGroup(recp) || _isFeed(recp))

    if (validRecps.length === 0) {
      // prettier-ignore
      throw new Error(`no box2 keys found for recipients: ${recps}`)
    }
    if (validRecps.length > 16) {
      // prettier-ignore
      throw new Error(`private-group spec allows maximum 16 slots, but you've tried to use ${validRecps.length}`)
    }
    // FIXME: move these validations to ssb-groups
    // if (validRecps.filter(isGroup).length === 0) {
    //   // prettier-ignore
    //   throw new Error(`no group keys found among recipients: ${recps}`)
    // }
    // if (!isGroup(validRecps[0])) {
    //   // prettier-ignore
    //   throw new Error(`first recipient must be a group, but you've tried to use ${validRecps[0]}`)
    // }
    const groupRecpsCount = validRecps.filter(_isGroup).length
    if (groupRecpsCount > 1) {
      // prettier-ignore
      throw new Error(`private-group spec only supports one group recipient, but you've tried to use ${groupRecpsCount}`)
    }

    const encryptionKeys = _keyring
      .encryptionKeys(authorId, validRecps)
      .filter((x) => x !== null)

    const msgSymmKey = new SecretKey().toBuffer()
    const authorIdBFE = BFE.encode(authorId)
    const previousMsgIdBFE = BFE.encode(previousId)

    const ciphertextBuf = box(
      plaintextBuf,
      authorIdBFE,
      previousMsgIdBFE,
      msgSymmKey,
      encryptionKeys
    )

    return ciphertextBuf
  }

  function decrypt(ciphertextBuf, opts) {
    const authorId = opts.author
    const authorBFE = BFE.encode(authorId)
    const previousBFE = BFE.encode(opts.previous)

    const { self, dm, group, poBox } = _keyring.decryptionKeys(authorId)

    const unboxWith = unbox.bind(null, ciphertextBuf, authorBFE, previousBFE)

    let plaintextBuf = null
    if ((plaintextBuf = unboxWith(group, ATTEMPT1))) return plaintextBuf
    if ((plaintextBuf = unboxWith(self, ATTEMPT16))) return plaintextBuf
    if ((plaintextBuf = unboxWith(dm, ATTEMPT16))) return plaintextBuf
    if ((plaintextBuf = unboxWith(poBox, ATTEMPT16))) return plaintextBuf

    return null
  }

  return {
    // ssb-encryption-format API:
    name: 'box2',
    setup,
    teardown,
    encrypt,
    decrypt,
    // ssb-box2 specific APIs:
    setOwnDMKey,
    addGroupInfo,
    listGroupIds,
    addKeypair,
  }
}

module.exports = makeEncryptionFormat
