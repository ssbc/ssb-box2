// SPDX-FileCopyrightText: 2021 Anders Rune Jensen
//
// SPDX-License-Identifier: LGPL-3.0-only

const makeEncryptionFormat = require('./format')

exports.name = 'box2'

exports.init = function (ssb, config) {
  const encryptionFormat = makeEncryptionFormat()
  if (ssb.db) ssb.db.installEncryptionFormat(encryptionFormat)

  return {
    setOwnDMKey: encryptionFormat.setOwnDMKey,
    addGroupKey: encryptionFormat.addGroupKey,
    listGroupKeys: encryptionFormat.listGroupKeys,
    addKeypair: encryptionFormat.addKeypair,
  }
}
