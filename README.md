CACrypt
=======
# CACrypt is nodejs package to perform encryption/decryption, signing/verifying. 

## Installation
```
npm install cacrypt --save
```

## Config
```
module.exports =
	keySize: 32 # A key size of 16 bytes will use AES-128, 24 => AES-192, 32 => AES-256
  	algorithm: 'AES-CBC'
  	message: 'Testing message'
```

## Usage
```
env = require('../env.coffee')
cacrypt = require('../index.coffee')(env)

```

## API
```
- cacrypt.encrypt *publickey* *message*
- cacrypt.decrypt *privatekey* *bundlewithmessage&key*
- cacrypt.sign *privatekey* *message*
- cacrypt.verify *publickey* *bundlewithmd&signature*

```
## Test
npm test


