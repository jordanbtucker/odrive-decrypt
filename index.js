const crypto = require('crypto')
const fs = require('fs')
const net = require('net')

module.exports = odriveDecrypt

const V_SIZE = 1
const S_SIZE = 64 / 8
const IV_SIZE = 128 / 8
const K_SIZE = 256 / 8
const HEADER_SIZE = V_SIZE + S_SIZE + IV_SIZE
const HASH_ALG = 'sha256'
const HASH_SIZE = 256 / 8

/**
 * To be confirmed. See https://forum.odrive.com/t/encryption-questions-key-storage-decryption-process-and-others/2094/3
 */
const KDF_ITER = 1000
const KDF_DIGEST = 'sha256'
const ENC_ALG = 'aes-256-cbc'

function odriveDecrypt (inFilename, passphrase, outFilename, callback) {
	const state = {}

	fs.open(inFilename, 'r', openInFileCallback)

	function openInFileCallback (err, fd) {
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
			outStream.on('end', () => {
				fs.stat(outFilename, outFileStatCallback)
			})
		} catch (err) {
			fs.unlink(outFilename)
			callback(err)
		}
	}

	function outFileStatCallback (err, stats) {
		if (err) {
			callback(err)
			return
		}

		if (stats.size < HASH_SIZE) {
			fs.unlink(outFilename)
			callback(new Error('Invalid hash'))
			return
		}

		state.size = stats.size
		fs.open(outFilename, 'r+', openOutFileCallback)
	}

	function openOutFileCallback (err, fd) {
		if (err) {
			callback(err)
			return
		}

		state.fd = fd

		const hashBuffer = Buffer.alloc(HASH_SIZE)

		fs.read(fd, hashBuffer, 0, HASH_SIZE, state.size - HASH_SIZE, readHashCallback)
	}

	function readHashCallback (err, hashBuffer) {
		if (err) {
			callback(err)
			return
		}

		state.hashBuffer = hashBuffer

		fs.ftruncate(state.fd, state.size - HASH_SIZE, truncateCallback)
	}

	function truncateCallback (err) {
		if (err) {
			callback(err)
			return
		}

		// Hack to move the file position to the start.
		fs.read(state.fd, Buffer.alloc(0), 0, 0, 0, moveToStartCallback)
	}

	function moveToStartCallback (err) {
		if (err) {
			callback(err)
			return
		}

		const hash = crypto.createHash(HASH_ALG)
		const stream = new net.Socket({ fd: state.fd, readable: true })
		stream.pipe(hash)

		hash.on('end', () => {
			const readHashBuffer = hash.read()

			if (state.hashBuffer.compare(readHashBuffer) !== 0) {
				callback(new Error('Invalid hash'))
				return
			}
		})
	}
}
