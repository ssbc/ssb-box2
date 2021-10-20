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

sbot.box2.addDMKey(testkey)

let content = { type: 'post', text: 'super secret', recps: [keys.id] }

sbot.db.publish(content, (err, privateMsg) => {
  // privateMsg is not encrypted using box2
})
```

## Methods

### addDMKey(key)

`key` must be a buffer. This key is only used to direct message (DM)
yourself. For direct messaging other feeds a key is automatically
derived.

### registerIsGroup(filter)

`filter` takes a recp and must return a boolean indicating if recp is
a group id or not. 

### addGroupKey(groupId, groupKey)

`groupId` must be a string and `groupKey` must be a buffer. The key
can then be used to send messages to the group. Note that keys are not
persisted in this module.

[SSB DB2]: https://github.com/ssb-ngi-pointer/ssb-db2/
[ssb-tribes]: https://github.com/ssbc/ssb-tribes/
