rest = require('./rest.coffee')
forge = require 'node-forge'
_ = require 'lodash'
					
# opts
# keySize: 32, 16 bytes will use AES-128, 24 => AES-192, 32 => AES-256
# Algorithm : AES-CBC
# serverurl: https://abc.com/api/user/:email				
module.exports = (opts = {}) ->
	encrypt: (receiverEmail, message) ->
		# Generate Symmetric key		
		key = forge.random.getBytesSync opts.keySize
		
		# Encrypt message  		
		cipher = forge.cipher.createCipher opts.algorithm, key
		cipher.start
		cipher.update forge.util.createBuffer message
		cipher.finish
		encryptedMessage = cipher.output.getBytes
	
		# get receiver public key
		rest.get "#{opts.serverurl}/api/user/#{receiverEmail}"
			.then (result) ->
				cert = _.last result.body.certs
				publicKey = forge.pki.publicKeyFromPem cert.publicKey
				
				# encrypt symmetric key with receiver public key
				encryptedKey = publicKey.encrypt(key)  
				return {
					encryptedMessage: encryptedMessage,
					encryptedKey: encryptedKey
				}
  			
	decrypt: (privateKey, bundle) ->
		encryptedMessage = bundle.encryptedMessage			
		encryptedKey = bundle.encryptedKey			
		key = privateKey.decrypt encryptedKey
		
		cipher = forge.cipher.createDecipher opts.algorithm, key
		cipher.start()
		cipher.update forge.util.createBuffer encryptedMessage
		if !cipher.finish()
			throw new Error 'Decryption failed'
		return cipher.output.getBytes()