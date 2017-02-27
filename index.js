/**
 * Decrypts files encrypted by oDrive.
 * @module odrive-decrypt
 */

const crypto = require('crypto')
const fs = require('fs')
const net = require('net')

module.exports = odriveDecrypt

/** Size of version information in bytes. */
const V_SIZE = 1

/** Size of KDF salt in bytes. */
const S_SIZE = 64 / 8

/** Size of IV in bytes. */
const IV_SIZE = 128 / 8

/** Size of encryption key in bytes. */
const K_SIZE = 256 / 8

/** Size of header information in bytes. */
const HEADER_SIZE = V_SIZE + S_SIZE + IV_SIZE

/**
 * Number of iterations used by KDF.
 * To be confirmed. See https://forum.odrive.com/t/encryption-questions-key-storage-decryption-process-and-others/2094/3
 */
const KDF_ITER = 1000

/** Digest used by KDF. */
const KDF_DIGEST = 'sha256'

/** Encryption algorigm. */
const ENC_ALG = 'aes-256-cbc'

/** Integrity hash algorigm. */
const HASH_ALG = 'sha256'

/** Integrity hash algorigm size in bytes. */
const HASH_SIZE = 256 / 8

/**
 * Decrypts a file encrypted by oDrive.
 * @param {string} inFilename The filename of the encrypted file.
 * @param {string} passphrase The passphrase used to encrypt the file.
 * @param {string} outFilename The location to save the decrypted file.
 * Overwriting the encrypted file is not supported.
 * @param {Function} callback Called when the file has been decrypted.
 * Accepts a single error argument.
 */
function odriveDecrypt (inFilename, passphrase, outFilename, callback) {
	// Store the state across function calls.
	const state = {}

	fs.open(inFilename, 'r', openInFileCallback)

	function openInFileCallback (err, fd) {
		if (err) {
			callback(err)
			return
		}

		state.fd = fd

		// Allocate a buffer to store the header which contains the version
		// byte, salt, and IV.
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

		// version is currently unused since we only know of one version of the
		// encryption process.
		const version = headerBuffer.slice(0, V_SIZE)
		const salt = headerBuffer.slice(V_SIZE, S_SIZE + V_SIZE)
		state.iv = headerBuffer.slice(V_SIZE + S_SIZE, V_SIZE + S_SIZE + IV_SIZE)

		// Use the passphrase and salt to derive the encryption key. We still
		// don't know what the number of iterations are.
		crypto.pbkdf2(passphrase, salt, KDF_ITER, K_SIZE, KDF_DIGEST, kdfCallback)
	}

	function kdfCallback (err, key) {
		if (err) {
			callback(err)
			return
		}

		try {
			// Create the decipher, open the streams for reading and writing,
			// and decrypt the file.
			const decipher = crypto.createDecipheriv(ENC_ALG, key, state.fd)
			const inStream = new net.Socket({ fd: state.fd, readable: true })
			const outStream = fs.createWriteStream(outFilename)
			inStream.pipe(decipher).pipe(outStream)
			outStream.on('end', () => {
				// The decrypted file contains the file contents followed by a
				// hash of the file contents, so we need to verify the hash and
				// remove it from the end of the file, starting by getting the
				// size of the file.
				fs.stat(outFilename, outFileStatCallback)
			})
		} catch (err) {
			// Since decryption failed at some point, delete whatever was
			// decrypted, if anything at all.
			fs.unlink(outFilename)
			callback(err)
		}
	}

	function outFileStatCallback (err, stats) {
		if (err) {
			callback(err)
			return
		}

		// If the decrypted file size is less than the hash size, then
		// the encrypted file is invalid.
		if (stats.size < HASH_SIZE) {
			fs.unlink(outFilename)
			callback(new Error('Invalid hash'))
			return
		}

		// Store the size from stats into the state, and open the decrypted
		// file for reading and writing since we need to verify the hash and
		// remove it.
		state.size = stats.size
		fs.open(outFilename, 'r+', openOutFileCallback)
	}

	function openOutFileCallback (err, fd) {
		if (err) {
			callback(err)
			return
		}

		state.fd = fd

		// Get the hash from the end of the decrypted file.
		const hashBuffer = Buffer.alloc(HASH_SIZE)
		fs.read(fd, hashBuffer, 0, HASH_SIZE, state.size - HASH_SIZE, readHashCallback)
	}

	function readHashCallback (err, hashBuffer) {
		if (err) {
			callback(err)
			return
		}

		// Store the hash for verification and remove the hash from the end of
		// the file.
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

		// Hash the decrypted file and verify that it matches the hash that was
		// at the end of the file.
		const hash = crypto.createHash(HASH_ALG)
		const stream = new net.Socket({ fd: state.fd, readable: true })
		stream.pipe(hash)

		hash.on('end', () => {
			const readHashBuffer = hash.read()

			// If the hash doesn't verify, then the encrypted file is corrupt.
			// Delete the decrypted file.
			if (state.hashBuffer.compare(readHashBuffer) !== 0) {
				fs.unlink(outFilename)
				callback(new Error('Invalid hash'))
				return
			}
		})
	}
}
