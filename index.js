const crypto = require('crypto')
const fs = require('fs')
const net = require('net')

module.exports = odriveDecrypt

/**
 * To be confirmed. See https://forum.odrive.com/t/encryption-questions-key-storage-decryption-process-and-others/2094/3
 */
const V_SIZE = 1
const S_SIZE = 64 / 8
const IV_SIZE = 128 / 8
const K_SIZE = 256 / 8
const HEADER_SIZE = V_SIZE + S_SIZE + IV_SIZE

/**
 * To be confirmed. See https://forum.odrive.com/t/encryption-questions-key-storage-decryption-process-and-others/2094/3
 */
const KDF_ITER = 1000
const KDF_DIGEST = 'sha256'
const ENC_ALG = 'aes-256-cbc'

function odriveDecrypt (inFilename, passphrase, outFilename, callback) {
	const state = {}

	fs.open(inFilename, 'r', openCallback)

	function openCallback (err, fd) {
		if (err) {
			callback(err)
			return
		}

		state.fd = fd

		const headerBuffer = Buffer.alloc(HEADER_SIZE)

		fs.read(fd, headerBuffer, 0, HEADER_SIZE, 0, readHeaderCallback)
	}

	function readHeaderCallback (err, bytesRead, headerBuffer) {
		if (err) {
			callback(err)
			return
		}

		if (bytesRead !== HEADER_SIZE) {
			callback(new Error('Invalid header'))
			return
		}

		const version = headerBuffer.slice(0, V_SIZE)
		const salt = headerBuffer.slice(V_SIZE, S_SIZE + V_SIZE)
		state.iv = headerBuffer.slice(V_SIZE + S_SIZE, V_SIZE + S_SIZE + IV_SIZE)

		crypto.pbkdf2(passphrase, salt, KDF_ITER, K_SIZE, KDF_DIGEST, kdfCallback)
	}

	function kdfCallback (err, key) {
		if (err) {
			callback(err)
			return
		}

		try {
			const decipher = crypto.createDecipheriv(ENC_ALG, key, state.fd)
			const inStream = new net.Socket({ fd: state.fd, readable: true })
			const outStream = fs.createWriteStream(outFilename)
			inStream.pipe(decipher).pipe(outStream)
		} catch (err) {
			callback(err)
		}
	}
}
