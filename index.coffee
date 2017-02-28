forge = require 'node-forge'
_ = require 'lodash'

			
# opts
# keySize: 32, 16 bytes will use AES-128, 24 => AES-192, 32 => AES-256
# Algorithm : AES-CBC			

module.exports = (opts = {}) ->
	encrypt: (pubkey, message) ->
		# Generate Symmetric key		
		key = forge.random.getBytesSync opts.keySize
		iv = forge.random.getBytesSync opts.keySize

		# Encrypt message
		cipher = forge.cipher.createCipher opts.algorithm, key
		cipher.start iv:iv
		cipher.update forge.util.createBuffer message
		cipher.finish()
		encryptedMessage = cipher.output.getBytes()
	
		# Get receiver public key
		publicKey = forge.pki.publicKeyFromPem pubkey
		
		# Encrypt symmetric key with receiver public key
		encryptedKey = publicKey.encrypt(key)  
		
		Promise.resolve {
			encryptedMessage: encryptedMessage,
			encryptedKey: encryptedKey,
			iv: iv
		}

  			
	decrypt: (prikey, bundle) ->
		encryptedMessage = bundle.encryptedMessage			
		encryptedKey = bundle.encryptedKey
		
		# Get receiver public key
		privateKey = forge.pki.privateKeyFromPem(forge.util.createBuffer prikey)
		
		# Decrypt symmetric key with receiver private key
		key = privateKey.decrypt encryptedKey
		
		# Decrypt message
		cipher = forge.cipher.createDecipher opts.algorithm, key
		cipher.start iv:bundle.iv
		cipher.update forge.util.createBuffer encryptedMessage
		if !cipher.finish()
			Promise.reject new Error 'Decryption failed'
		Promise.resolve cipher.output.getBytes()


												
