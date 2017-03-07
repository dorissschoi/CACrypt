cacrypt = require('../index.coffee')()
expect = require('chai').expect
keypair = require 'keypair'
pair = keypair()
bundle = {}

message = 'testing'

describe '#Encryption ', ->
	it 'Encryption ', (done) ->
		bundle = cacrypt.encrypt(pair.public, message)		
		expect(bundle).to.exist
		done()
		return

describe '#Decryption ', ->		
	it 'Decryption ', (done) ->
		decryptedMsg = cacrypt.decrypt(pair.private, bundle)
		expect(decryptedMsg).to.equal(message)
		done()
		return
		
describe '#Signing ', ->
	it 'Signing ', (done) ->
		bundle = cacrypt.sign(pair.private, bundle.encryptedMessage)
		expect(bundle).to.exist
		done()
		return
		
describe '#Verifying ', ->		
	it 'Verifying ', (done) ->
		verified = cacrypt.verify(pair.public, bundle)
		expect(verified).to.be.true
		done()	
		return
				