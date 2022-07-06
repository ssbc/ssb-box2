// SPDX-FileCopyrightText: 2022 Andre 'Staltz' Medeiros
//
// SPDX-License-Identifier: LGPL-3.0-only

const BFE = require('ssb-bfe')
const Ref = require('ssb-ref')
const Uri = require('ssb-uri2')
const path = require('path')
const os = require('os')
const { box, unboxKey, unboxBody } = require('envelope-js')
const { SecretKey } = require('ssb-private-group-keys')
const Keyring = require('ssb-keyring')

const name = 'box2'

let _keyring = null

function reportError(err) {
  if (err) console.error(err)
}

function setup(config, cb) {
  const keyringPath = path.join(
    config.path || path.join(os.tmpdir(), '.ssb-keyring-' + Date.now()),
    'keyring'
  )
  _keyring = Keyring(keyringPath, cb)
  _keyring.keypair.add(config.keys.id, config.keys, reportError)
}

function _isGroup(recp) {
  return _keyring.group.has(recp)
}

function _isFeed(recp) {
  return (
    Ref.isFeed(recp) ||
    Uri.isFeedSSBURI(recp) ||
    Uri.isBendyButtV1FeedSSBURI(recp) ||
    Uri.isButtwooV1FeedSSBURI(recp)
  )
}

function setOwnDMKey(key) {
  _keyring.own.set({ key }, reportError)
}

function addGroupKey(id, key) {
  _keyring.group.add(id, { key }, reportError)
}

function addKeypair(id, keypair) {
  _keyring.keypair.add(id, keypair, reportError)
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

  const encryptionKeys = _keyring.encryptionKeys(authorId, validRecps)

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

  const decryptionKeys = _keyring.decryptionKeys(authorId)

  const readKeyFromGroup = unboxKey(
    ciphertextBuf,
    authorBFE,
    previousBFE,
    decryptionKeys,
    { maxAttempts: 16 }
  )
  // FIXME: maxAttempts should be PER KEY, because groupKeys do 1 attempt,
  // DM keys do 16 attempts. This requires changing envelope-js.

  if (readKeyFromGroup)
    return unboxBody(ciphertextBuf, authorBFE, previousBFE, readKeyFromGroup)

  return null
}

module.exports = {
  // ssb-encryption-format API:
  name,
  setup,
  encrypt,
  decrypt,
  // ssb-box2 specific APIs:
  setOwnDMKey,
  addGroupKey,
  addKeypair,
}
