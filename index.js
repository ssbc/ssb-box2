// SPDX-FileCopyrightText: 2021 Anders Rune Jensen
//
// SPDX-License-Identifier: LGPL-3.0-only

const makeEncryptionFormat = require('./format')
const monitorForest = require('./monitor')

exports.name = 'box2'

exports.init = function (ssb, config) {
  const encryptionFormat = makeEncryptionFormat()
  if (ssb.db) ssb.db.installEncryptionFormat(encryptionFormat)

  if (config.box2 && config.box2.legacyMode) {
    encryptionFormat.addSigningKeys(config.keys.id, config.keys)
  } else if (!ssb.metafeeds) {
    throw new Error('ssb-box2 requires ssb-meta-feeds plugin')
  } else {
    encryptionFormat.disableLegacyMode()
    monitorForest(ssb, encryptionFormat)
  }

  return {
    setOwnDMKey: encryptionFormat.setOwnDMKey,
    addSigningKeys: encryptionFormat.addSigningKeys,
    addGroupInfo: encryptionFormat.addGroupInfo,
    listGroupIds: encryptionFormat.listGroupIds,
    getGroupKeyInfo: encryptionFormat.getGroupKeyInfo,
  }
}
