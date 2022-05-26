<!--
SPDX-FileCopyrightText: 2021 Anders Rune Jensen

SPDX-License-Identifier: CC0-1.0
-->

# SSB-DB2-Box2

A module for working with box2 in [SSB DB2]. Messages created using
this module is compatible with [ssb-tribes].

## Usage

Encrypt a message to self using box2.

```js
const SecretStack = require('secret-stack')
const caps = require('ssb-caps')
const ssbKeys = require('ssb-keys')

const keys = ssbKeys.loadOrCreateSync(path.join(dir, 'secret'))

const sbot = SecretStack({ caps })
  .use(require('ssb-db2'))
  .use(require('ssb-db2-box2'))
  .call(null, {
     path: './',
     keys,
     box2: {
       alwaysbox2: true
     }
  })

const testkey = Buffer.from(
  '30720d8f9cbf37f6d7062826f6decac93e308060a8aaaa77e6a4747f40ee1a76',
  'hex'
)

sbot.box2.addOwnDMKey(testkey)
sbot.box2.setReady()

let content = { type: 'post', text: 'super secret', recps: [keys.id] }

sbot.db.publish(content, (err, privateMsg) => {
  // privateMsg is now encrypted using box2
})
```

## Configuration

SSB-DB2-BOX2 supports ssb-config parameters to configure things:

```js
const config = {
  box2: {
    /*
      This variable is only for DMs. Group messages are always using box2.
      For DMs, the problem is figuring out if the other side supports
      box2 or not. We expect to be able to use metafeeds to determine this
      in the future. For now you can use this variable to use box2 for all
      DMs, otherwise box1 will be used for all.
    */
    alwaysbox2: true
  }
}
```

## Methods

### addOwnDMKey(key)

`key` must be a buffer. By specifying the direct message (DM) for
yourself, you are free to supply that from any source. This could be a
key stored in [ssb-keyring], a key derived from the seed in meta feeds
or simply a temporary key. For direct messaging other feeds a key is
automatically derived.

### registerIsGroup(filter)

`filter` takes a recp and must return a boolean indicating if recp is
a group id or not.

### addGroupKey(groupId, groupKey)

`groupId` must be a string and `groupKey` must be a buffer. The key
can then be used to send messages to the group. Note that keys are not
persisted in this module.

### getGroupKey(groupId)

Returns the `groupKey` as a buffer or undefined if group key is not
found.

### setReady()

On startup, once all keys have been added be sure to call `setReady`
to signal to DB2 that it is now safe to process data.

### isReady(cb)

`cb` will resolve once once all initial keys have been added.

[SSB DB2]: https://github.com/ssb-ngi-pointer/ssb-db2/
[ssb-tribes]: https://github.com/ssbc/ssb-tribes/
[ssb-keyring]: https://gitlab.com/ahau/lib/ssb-keyring/
