// SPDX-FileCopyrightText: 2021 Anders Rune Jensen
//
// SPDX-License-Identifier: LGPL-3.0-only

const { directMessageKey } = require('ssb-private-group-keys')
const { keySchemes } = require('private-group-spec')

module.exports = function makeKeysManager(config) {
  const ownDMKeysCache = []
  const sharedDMKeysCache = new Map()
  const groupKeysCache = new Map()

  function addOwnDMKey(key) {
    ownDMKeysCache.push(key)
  }

  function ownDMKeys() {
    return ownDMKeysCache.map((key) => {
      return { key, scheme: keySchemes.feed_id_self }
    })
  }

  const buildSharedDMKey = directMessageKey.easy(config.keys)

  function sharedDMKey(author) {
    if (!sharedDMKeysCache.has(author)) {
      sharedDMKeysCache.set(author, buildSharedDMKey(author))
    }
    return sharedDMKeysCache.get(author)
  }

  function addGroupKey(id, key) {
    groupKeysCache.set(id, key)
  }

  function groupKey(id) {
    if (groupKeysCache.has(id)) {
      return { key: groupKeysCache.get(id), scheme: keySchemes.private_group }
    } else {
      return undefined
    }
  }

  function groupKeys() {
    return [...groupKeysCache.values()].map((key) => {
      return { key, scheme: keySchemes.private_group }
    })
  }

  return {
    addOwnDMKey,
    ownDMKeys,

    sharedDMKey,

    addGroupKey,
    groupKey,
    groupKeys,
  }
}
