import com.google.common.primitives.Bytes
import org.bouncycastle.crypto.digests.Blake2sDigest
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import java.util.Base64

const val KEY_LENGTH = 32
const val AUTH_TAG_LENGTH = 16

@JvmInline
value class Key(val value: ByteArray) {
    init { require(value.size == KEY_LENGTH) }
    fun toBase64(): String = Base64.getEncoder().encodeToString(value)
    override fun toString(): String = "Key(${toBase64().take(8)}...)"
    companion object {
        fun fromBase64(base64: String): Key {
            val decoded = Base64.getDecoder().decode(base64)
            require(decoded.size == KEY_LENGTH)
            return Key(decoded)
        }
    }
}

fun generateKeyPair(): Pair<Key, Key> {
    val privateKeyBytes = ByteArray(KEY_LENGTH).apply { SecureRandom().nextBytes(this) }
    clampPrivateKey(privateKeyBytes)
    val privateKey = Key(privateKeyBytes)
    return Pair(privateKey, privateToPublicKey(privateKey))
}

fun privateToPublicKey(privateKey: Key): Key {
    val basePoint = ByteArray(KEY_LENGTH).apply { this[0] = 9 }
    return Key(x25519(privateKey, Key(basePoint)))
}

private fun clampPrivateKey(key: ByteArray) {
    key[0] = (key[0].toInt() and 248).toByte()
    key[31] = (key[31].toInt() and 127).toByte()
    key[31] = (key[31].toInt() or 64).toByte()
}

fun x25519(privateKey: Key, publicKey: Key): ByteArray {
    val secret = ByteArray(KEY_LENGTH)
    val clampedPrivateKey = privateKey.value.clone().also { clampPrivateKey(it) }
    val pKey = X25519PrivateKeyParameters(clampedPrivateKey, 0)
    val agreement = org.bouncycastle.crypto.agreement.X25519Agreement()
    agreement.init(pKey)
    agreement.calculateAgreement(X25519PublicKeyParameters(publicKey.value, 0), secret, 0)
    return secret
}

object Aead {
    fun chacha20Poly1305Encrypt(key: Key, counter: Long, plaintext: ByteArray, associatedData: ByteArray): ByteArray {
        val nonce = ByteArray(12).apply { ByteBuffer.wrap(this, 4, 8).order(ByteOrder.LITTLE_ENDIAN).putLong(counter) }
        val cipher = ChaCha20Poly1305()
        cipher.init(true, AEADParameters(KeyParameter(key.value), AUTH_TAG_LENGTH * 8, nonce, associatedData))
        val ciphertext = ByteArray(cipher.getOutputSize(plaintext.size))
        val len = cipher.processBytes(plaintext, 0, plaintext.size, ciphertext, 0)
        cipher.doFinal(ciphertext, len)
        return ciphertext
    }

    fun chacha20Poly1305Decrypt(key: Key, counter: Long, ciphertext: ByteArray, associatedData: ByteArray): ByteArray? {
        return try {
            val nonce = ByteArray(12).apply { ByteBuffer.wrap(this, 4, 8).order(ByteOrder.LITTLE_ENDIAN).putLong(counter) }
            val cipher = ChaCha20Poly1305()
            cipher.init(false, AEADParameters(KeyParameter(key.value), AUTH_TAG_LENGTH * 8, nonce, associatedData))
            val plaintext = ByteArray(cipher.getOutputSize(ciphertext.size))
            val len = cipher.processBytes(ciphertext, 0, ciphertext.size, plaintext, 0)
            cipher.doFinal(plaintext, len)
            plaintext
        } catch (e: Exception) { null }
    }

    fun xchacha20Poly1305Encrypt(key: Key, nonce: ByteArray, plaintext: ByteArray, associatedData: ByteArray): ByteArray {
        require(nonce.size == 24)
        val subkey = hchacha20(key.value, nonce.sliceArray(0..15))
        val shortNonce = ByteArray(12).apply { System.arraycopy(nonce, 16, this, 4, 8) }
        val cipher = ChaCha20Poly1305()
        cipher.init(true, AEADParameters(KeyParameter(subkey), AUTH_TAG_LENGTH * 8, shortNonce, associatedData))
        val ciphertext = ByteArray(cipher.getOutputSize(plaintext.size))
        val len = cipher.processBytes(plaintext, 0, plaintext.size, ciphertext, 0)
        cipher.doFinal(ciphertext, len)
        return ciphertext
    }

    fun xchacha20Poly1305Decrypt(key: Key, nonce: ByteArray, ciphertext: ByteArray, associatedData: ByteArray): ByteArray? {
        require(nonce.size == 24)
        return try {
            val subkey = hchacha20(key.value, nonce.sliceArray(0..15))
            val shortNonce = ByteArray(12).apply { System.arraycopy(nonce, 16, this, 4, 8) }
            val cipher = ChaCha20Poly1305()
            cipher.init(false, AEADParameters(KeyParameter(subkey), AUTH_TAG_LENGTH * 8, shortNonce, associatedData))
            val plaintext = ByteArray(cipher.getOutputSize(ciphertext.size))
            val len = cipher.processBytes(ciphertext, 0, ciphertext.size, plaintext, 0)
            cipher.doFinal(plaintext, len)
            plaintext
        } catch (e: Exception) { null }
    }

    private fun hchacha20(key: ByteArray, nonce: ByteArray): ByteArray {
        val state = IntArray(16)
        val keyBuf = ByteBuffer.wrap(key).order(ByteOrder.LITTLE_ENDIAN)
        val nonceBuf = ByteBuffer.wrap(nonce).order(ByteOrder.LITTLE_ENDIAN)
        state[0] = 0x61707865; state[1] = 0x3320646e; state[2] = 0x79622d32; state[3] = 0x6b206574
        for (i in 0..7) state[4 + i] = keyBuf.getInt(i * 4)
        for (i in 0..3) state[12 + i] = nonceBuf.getInt(i * 4)
        val x = state.clone()
        repeat(10) {
            quarterRound(x, 0, 4, 8, 12); quarterRound(x, 1, 5, 9, 13); quarterRound(x, 2, 6, 10, 14); quarterRound(x, 3, 7, 11, 15)
            quarterRound(x, 0, 5, 10, 15); quarterRound(x, 1, 6, 11, 12); quarterRound(x, 2, 7, 8, 13); quarterRound(x, 3, 4, 9, 14)
        }
        val outBuf = ByteBuffer.allocate(32).order(ByteOrder.LITTLE_ENDIAN)
        for (i in 0..3) outBuf.putInt(x[i])
        for (i in 12..15) outBuf.putInt(x[i])
        return outBuf.array()
    }

    private fun quarterRound(x: IntArray, a: Int, b: Int, c: Int, d: Int) {
        x[a] += x[b]; x[d] = (x[d] xor x[a]).rotateLeft(16)
        x[c] += x[d]; x[b] = (x[b] xor x[c]).rotateLeft(12)
        x[a] += x[b]; x[d] = (x[d] xor x[a]).rotateLeft(8)
        x[c] += x[d]; x[b] = (x[b] xor x[c]).rotateLeft(7)
    }
}

fun hash(vararg data: ByteArray): ByteArray {
    val digest = Blake2sDigest(32)
    data.forEach { digest.update(it, 0, it.size) }
    val out = ByteArray(32)
    digest.doFinal(out, 0)
    return out
}

fun mac(key: ByteArray, vararg data: ByteArray): ByteArray {
    val digest = Blake2sDigest(key, 16, null, null)
    data.forEach { digest.update(it, 0, it.size) }
    val out = ByteArray(16)
    digest.doFinal(out, 0)
    return out
}

private fun hmac(key: ByteArray, vararg data: ByteArray): ByteArray {
    val hmac = HMac(Blake2sDigest(32))
    hmac.init(KeyParameter(key))
    data.forEach { hmac.update(it, 0, it.size) }
    val result = ByteArray(32)
    hmac.doFinal(result, 0)
    return result
}

fun kdf1(ck: ByteArray, input: ByteArray): ByteArray {
    val temp = hmac(ck, input)
    return hmac(temp, byteArrayOf(0x01))
}

fun kdf2(ck: ByteArray, input: ByteArray): Pair<ByteArray, Key> {
    val temp = hmac(ck, input)
    val key1 = hmac(temp, byteArrayOf(0x01))
    val key2 = hmac(temp, Bytes.concat(key1, byteArrayOf(0x02)))
    return Pair(key1, Key(key2))
}

fun kdf3(ck: ByteArray, input: ByteArray): Triple<ByteArray, Key, Key> {
    val temp = hmac(ck, input)
    val key1 = hmac(temp, byteArrayOf(0x01))
    val key2 = hmac(temp, Bytes.concat(key1, byteArrayOf(0x02)))
    val key3 = hmac(temp, Bytes.concat(key2, byteArrayOf(0x03)))
    return Triple(key1, Key(key2), Key(key3))
}

fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
    if (a.size != b.size) return false
    var result = 0
    for (i in a.indices) {
        result = result or (a[i].toInt() xor b[i].toInt())
    }
    return result == 0
}