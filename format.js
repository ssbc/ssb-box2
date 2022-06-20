// SPDX-FileCopyrightText: 2022 Andre 'Staltz' Medeiros
//
// SPDX-License-Identifier: LGPL-3.0-only

const BFE = require('ssb-bfe')
const Ref = require('ssb-ref')
const Uri = require('ssb-uri2')
const { box, unboxKey, unboxBody } = require('envelope-js')
const { SecretKey } = require('ssb-private-group-keys')
const makeKeysManager = require('./keys')

const name = 'box2'

let _keysManager = null
let _selfId = null

function setup(config, cb) {
  _selfId = config.keys.id
  _keysManager = makeKeysManager(config)
  // FIXME: load ssb-keyring here
  cb()
}

function _isGroup(recp) {
  return _keysManager.groupKey(recp) !== undefined
}

function _isFeed(recp) {
  return (
    Ref.isFeed(recp) ||
    Uri.isFeedSSBURI(recp) ||
    Uri.isBendyButtV1FeedSSBURI(recp) ||
    Uri.isButtwooV1FeedSSBURI(recp)
  )
}

function addOwnDMKey(key) {
  _keysManager.addOwnDMKey(key)
}

function addGroupKey(id, key) {
  _keysManager.addGroupKey(id, key)
}

function encrypt(plaintextBuf, opts) {
  const recps = opts.recps
  const selfId = opts.keys.id

  const validRecps = recps
    .filter((recp) => typeof recp === 'string')
    .filter((recp) => recp === selfId || _isGroup(recp) || _isFeed(recp))

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

  const encryptionKeys = validRecps.reduce((acc, recp) => {
    if (recp === selfId) return [...acc, ..._keysManager.ownDMKeys()]
    else if (_isGroup(recp)) return [...acc, _keysManager.groupKey(recp)]
    else if (_isFeed(recp)) return [...acc, _keysManager.sharedDMKey(recp)]
  }, [])

  const msgSymmKey = new SecretKey().toBuffer()
  const authorIdBFE = BFE.encode(opts.keys.id)
  const previousMsgIdBFE = BFE.encode(opts.previous)

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
  const authorBFE = BFE.encode(opts.author)
  const previousBFE = BFE.encode(opts.previous)

  const trialGroupKeys = _keysManager.groupKeys()
  const readKeyFromGroup = unboxKey(
    ciphertextBuf,
    authorBFE,
    previousBFE,
    trialGroupKeys,
    { maxAttempts: 1 }
  )
  // NOTE the group recp is only allowed in the first slot,
  // so we only test group keys in that slot (maxAttempts: 1)
  if (readKeyFromGroup)
    return unboxBody(ciphertextBuf, authorBFE, previousBFE, readKeyFromGroup)

  const trialDMKeys =
    opts.author !== _selfId
      ? [_keysManager.sharedDMKey(opts.author), ..._keysManager.ownDMKeys()]
      : _keysManager.ownDMKeys()

  const readKey = unboxKey(ciphertextBuf, authorBFE, previousBFE, trialDMKeys, {
    maxAttempts: 16,
  })

  if (readKey) return unboxBody(ciphertextBuf, authorBFE, previousBFE, readKey)
  else return null
}

module.exports = {
  // ssb-encryption-format API:
  name,
  setup,
  encrypt,
  decrypt,
  // ssb-box2 specific APIs:
  addOwnDMKey,
  addGroupKey,
}
