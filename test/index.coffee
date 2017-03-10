cacrypt = require('../index.coffee')()
expect = require('chai').expect
keypair = require 'keypair'
pair = keypair()
bundle = {}

message = 'testing'

describe '#Stream Encryption ', ->
	it 'Stream Encryption ', (done) ->
		bundle = cacrypt.encryptStream(pair.public, './test/datafile.txt', './test/enfile.txt')
		expect(bundle).to.exist
		done()
		return

describe '#Stream Decryption ', ->		
	it 'Stream Decryption ', (done) ->
		decryptedMsg = cacrypt.decryptStream(pair.private, bundle, './test/enfile.txt', './test/resultfile.txt')
		expect(decryptedMsg).to.exist
		done()
		return		

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
			