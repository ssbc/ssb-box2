// SPDX-FileCopyrightText: 2021 Anders Rune Jensen
//
// SPDX-License-Identifier: LGPL-3.0-only

const encryptionFormat = require('./format')

exports.name = 'box2'

exports.init = function (ssb, config) {
  if (ssb.db) ssb.db.installEncryptionFormat(encryptionFormat)

  return {
    addOwnDMKey: encryptionFormat.addOwnDMKey,
    addGroupKey: encryptionFormat.addGroupKey,
  }
}
