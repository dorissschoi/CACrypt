env = require('../env.coffee')
cacrypt = require('../index.coffee')(env)
expect = require('chai').expect
keypair = require 'keypair'
pair = keypair()
buddle = {}

describe '#Encryption ', ->
	it 'Encryption ', (done) ->
		cacrypt.encrypt(pair.public, env.message)
			.then (data) ->
				expect(data).to.exist
				buddle = data
				done()	
		return

describe '#Decryption ', ->		
	it 'Decryption ', (done) ->
		cacrypt.decrypt(pair.private, buddle)
			.then (data) ->
				expect(data).to.equal(env.message)
				done()	
		return