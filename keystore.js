// SPDX-FileCopyrightText: 2021 Anders Rune Jensen
//
// SPDX-License-Identifier: AGPL-3.0-only

const { directMessageKey } = require('ssb-private-group-keys')
const bfe = require('ssb-bfe')
const { keySchemes } = require('private-group-spec')

module.exports = function (config, isGroup) {
  const dmCache = {}

  const buildDMKey = directMessageKey.easy(config.keys)

  function sharedDMKey(author) {
    if (!dmCache[author]) dmCache[author] = buildDMKey(author)

    return dmCache[author]
  }

  let ownKeys = []

  function addDMKey(key) {
    ownKeys.push(key)
  }

  function ownDMKeys() {
    return ownKeys.map((key) => {
      return { key, scheme: keySchemes.feed_id_self }
    })
  }

  let allGroupKeys = {}

  function addGroupKey(id, key) {
    allGroupKeys[id] = key
  }

  function groupKey(id) {
    const key = allGroupKeys[id]
    if (key) return { key, scheme: keySchemes.private_group }
    else return undefined
  }

  function groupKeys() {
    return Object.values(allGroupKeys).map((key) => {
      return { key, scheme: keySchemes.private_group }
    })
  }

  return {
    ownDMKeys,
    TFKId: bfe.encode(config.keys.id),
    sharedDMKey,
    addDMKey,

    addGroupKey,
    groupKey,
    groupKeys,
  }
}
