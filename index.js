// SPDX-FileCopyrightText: 2021 Anders Rune Jensen
//
// SPDX-License-Identifier: AGPL-3.0-only

const bfe = require('ssb-bfe')
const { box, unboxKey, unboxBody } = require('envelope-js')
const { SecretKey } = require('ssb-private-group-keys')
const bendy = require('ssb-bendy-butt')
const { isFeed } = require('ssb-ref')
const DeferredPromise = require('p-defer')

const Keys = require('./keys')

exports.name = 'box2'

exports.init = function (sbot, config) {
  if (!sbot.db) throw new Error('ssb-db2-box2 requires ssb-db2')

  const sbotId = config.keys.id
  const keys = Keys(config)

  // default
  function isGroup(recipient) {
    return false
  }

  function registerIsGroup(f) {
    isGroup = f
  }

  function validateRecipients(recipients) {
    if (recipients.length > 16)
      throw new Error(
        `private-group spec allows maximum 16 slots, but you've tried to use ${recipients.length}`
      )

    // groupId can only be in first "slot"
    if (!isGroup(recipients[0]) && !isFeed(recipients[0]))
      throw new Error('first recipient must be a group or feed')

    if (recipients.length > 1 && !recipients.slice(1).every(isFeed))
      throw new Error('only feeds are supported as recipients')
  }

  function getKeys(recipients) {
    return recipients.reduce((acc, recp) => {
      if (recp === config.keys.id) return [...acc, ...keys.ownDMKeys()]
      else if (isGroup(recp)) return [...acc, keys.groupKey(recp)]
      else return [...acc, keys.sharedDMKey(recp)]
    }, [])
  }

  function encryptClassic(keys, content, previous) {
    validateRecipients(content.recps)

    const recipientKeys = getKeys(content.recps)

    if (recipientKeys.length == 0)
      throw new Error(`no keys found for recipients: ${content.recps}`)

    const plaintext = Buffer.from(JSON.stringify(content), 'utf8')
    const msgKey = new SecretKey().toBuffer()
    let previousMessageId = bfe.encode(previous)
    const authorId = bfe.encode(keys.id)

    const envelope = box(
      plaintext,
      authorId,
      previousMessageId,
      msgKey,
      recipientKeys
    )

    return envelope.toString('base64') + '.box2'
  }

  function encryptBendyButt(
    encodedAuthor,
    encodedContent,
    encodedPrevious,
    recps
  ) {
    validateRecipients(recps)

    const recipientKeys = getKeys(recps)

    if (recipientKeys.length == 0)
      throw new Error(`no keys found for recipients: ${recps}`)

    const msgKey = new SecretKey().toBuffer()

    const envelope = box(
      encodedContent,
      encodedAuthor,
      encodedPrevious,
      msgKey,
      recipientKeys
    )

    // maybe just return envelope directly?
    return envelope.toString('base64') + '.box2'
  }


  const FEED = bfe.bfeNamedTypes['feed']
  const CLASSIC_FEED_TF = Buffer.from([FEED.code, FEED.formats['classic'].code])

  function decryptBox2Msg(envelope, feedId, prevMsgId, readKey) {
    const plaintext = unboxBody(envelope, feedId, prevMsgId, readKey)
    if (plaintext) {
      if (feedId.slice(0, 2).equals(CLASSIC_FEED_TF))
        return JSON.parse(plaintext.toString('utf8'))
      else
        return bendy.decodeBox2(plaintext)
    }
    else return ''
  }

  function decryptBox2(ciphertext, author, previous) {
    const envelope = Buffer.from(ciphertext.replace('.box2', ''), 'base64')
    let authorBFE = bfe.encode(author)
    let previousBFE = bfe.encode(previous)

    const trialGroupKeys = keys.groupKeys()
    const readKeyFromGroup = unboxKey(envelope, authorBFE, previousBFE,
                                      trialGroupKeys, { maxAttempts: 1 })
    // NOTE the group recp is only allowed in the first slot,
    // so we only test group keys in that slot (maxAttempts: 1)
    if (readKeyFromGroup)
      return decryptBox2Msg(envelope, authorBFE, previousBFE, readKeyFromGroup)

    const trialDMKeys = author !== sbotId ?
          [keys.sharedDMKey(author), ...keys.ownDMKeys()] :
          keys.ownDMKeys()

    readKey = unboxKey(envelope, authorBFE, previousBFE, trialDMKeys, {
      maxAttempts: 16,
    })

    if (readKey)
      return decryptBox2Msg(envelope, authorBFE, previousBFE, readKey)
    else return ''
  }

  // obz?
  const ready = DeferredPromise()
  function setReady() {
    ready.resolve()
  }

  // FIXME: maybe if a feed has a meta feed, then we can assume it
  // does box2 as well
  function supportsBox2(feedId) {
    if (config.box2 && config.box2.alwaysbox2) return true
    else if (isGroup(feedId)) return true
    else return false
  }

  function isReady(cb) {
    ready.promise.then(cb)
  }

  function hasOwnDMKey() {
    return keys.ownDMKeys().length > 0
  }

  return {
    // db2
    supportsBox2,
    encryptClassic,
    encryptBendyButt,
    decryptBox2,

    registerIsGroup,
    addOwnDMKey: keys.addDMKey,
    hasOwnDMKey,
    addGroupKey: keys.addGroupKey,
    setReady,
    isReady
  }
}
