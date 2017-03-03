env = require('../env.coffee')
cacrypt = require('../index.coffee')(env)
expect = require('chai').expect
keypair = require 'keypair'
pair = keypair()
bundle = {}

describe '#Encryption ', ->
	it 'Encryption ', (done) ->
		cacrypt.encrypt(pair.public, env.message)
			.then (data) ->
				expect(data).to.exist
				bundle = data
				done()	
		return

describe '#Decryption ', ->		
	it 'Decryption ', (done) ->
		cacrypt.decrypt(pair.private, bundle)
			.then (data) ->
				expect(data).to.equal(env.message)
				done()	
		return
		
describe '#Signing ', ->
	it 'Signing ', (done) ->
		cacrypt.sign(pair.private, bundle.encryptedMessage)
			.then (data) ->
				expect(data).to.exist
				bundle = data
				done()
		return
		
describe '#Verifying ', ->		
	it 'Verifying ', (done) ->
		cacrypt.verify(pair.public, bundle)
			.then (data) ->
				expect(data).to.be.true
				done()	
		return				