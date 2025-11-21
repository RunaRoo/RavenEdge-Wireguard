import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import java.util.Arrays
import java.util.concurrent.atomic.AtomicLong


// --- Protocol Constants ---
val PROTOCOL_NAME = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".toByteArray()
val IDENTIFIER = "WireGuard v1 zx2c4 Jason@zx2c4.com".toByteArray()
val LABEL_MAC1 = "mac1----".toByteArray() //Fixed
val LABEL_COOKIE = "cookie--".toByteArray()

/**
 * Implements the stateless WireGuard Noise Protocol Handshake logic.
 * This class is a direct port of the cryptographic state machine from the boringtun (Rust) implementation.
 * It does not hold state itself but calculates handshake messages and session keys based on the state passed to it.
 */
class Noise(
    private val localStaticPrivate: Key,
    val localStaticPublic: Key,
    private val remoteStaticPublic: Key,
    private val presharedKey: Key?
) {
    private val initialChainingKey = hash(PROTOCOL_NAME)
    private val initialHash = hash(initialChainingKey, IDENTIFIER)

    /**
     * Creates the first message in a handshake (Initiation).
     * This is called by the peer acting as the client/initiator.
     */
    fun createHandshakeInitiation(senderIndex: Int): Pair<HandshakeInitiationMessage, HandshakeSecrets> {
        var ck = initialChainingKey.clone()
        var hs = initialHash.clone()

        // h = HASH(h, remote_static_public)
        hs = hash(hs, remoteStaticPublic.value)

        val (ephemeralPrivate, ephemeralPublic) = generateKeyPair()
        val message = HandshakeInitiationMessage(senderIndex, ephemeralPublic, ByteArray(48), ByteArray(28), ByteArray(16), ByteArray(16))

        // h = HASH(h, ephemeral_public)
        hs = hash(hs, message.unencryptedEphemeral.value)

        // ck = KDF1(ck, ephemeral_public)
        ck = kdf1(ck, message.unencryptedEphemeral.value)

        // (ck, k) = KDF2(ck, DH(ephemeral_private, remote_static_public))
        val sharedSecret1 = x25519(ephemeralPrivate, remoteStaticPublic)
        val (ck1, key1) = kdf2(ck, sharedSecret1)
        ck = ck1

        message.encryptedStatic = Aead.chacha20Poly1305Encrypt(key1, 0, localStaticPublic.value, hs)
        hs = hash(hs, message.encryptedStatic)

        // (ck, k) = KDF2(ck, DH(local_static_private, remote_static_public))
        val sharedSecret2 = x25519(localStaticPrivate, remoteStaticPublic)
        val (ck2, key2) = kdf2(ck, sharedSecret2)
        ck = ck2

        val timestamp = tai64n()
        message.encryptedTimestamp = Aead.chacha20Poly1305Encrypt(key2, 0, timestamp, hs)
        hs = hash(hs, message.encryptedTimestamp)

        presharedKey?.let { psk ->
            val (ck3, tau, _) = kdf3(ck, psk.value)
            ck = ck3
            hs = hash(hs, tau.value)
        }

        val mac1Key = hash(LABEL_MAC1, remoteStaticPublic.value)
        message.mac1 = mac(mac1Key, message.bytesForMacs())

        val secrets = HandshakeSecrets(ck, hs, ephemeralPrivate)
        return Pair(message, secrets)
    }

    /**
     * Consumes the second message in a handshake (Response) to derive session keys.
     * This is called by the peer acting as the client/initiator.
     */
    fun consumeHandshakeResponse(secrets: HandshakeSecrets, response: HandshakeResponseMessage): KeyPair? {
        var ck = secrets.chainingKey
        var hs = secrets.hash

        // h = HASH(h, remote_ephemeral_public)
        hs = hash(hs, response.unencryptedEphemeral.value)

        // ck = KDF1(ck, remote_ephemeral_public)
        ck = kdf1(ck, response.unencryptedEphemeral.value)

        // ck = KDF1(ck, DH(local_ephemeral, remote_ephemeral))
        val sharedSecret1 = x25519(secrets.ephemeralPrivate, response.unencryptedEphemeral)
        ck = kdf1(ck, sharedSecret1)

        // ck = KDF1(ck, DH(local_static, remote_ephemeral))
        val sharedSecret2 = x25519(localStaticPrivate, response.unencryptedEphemeral)
        ck = kdf1(ck, sharedSecret2)

        var key: Key
        presharedKey?.let { psk ->
            val (ck3, tau, k) = kdf3(ck, psk.value)
            ck = ck3
            hs = hash(hs, tau.value)
            key = k
        } ?: run {
            val (ck2, k) = kdf2(ck, ByteArray(0))
            ck = ck2
            key = k
        }

        val decryptedNothing = Aead.chacha20Poly1305Decrypt(key, 0, response.encryptedNothing, hs)
        if (decryptedNothing == null || decryptedNothing.isNotEmpty()) return null

        // Final key derivation
        val (sendKeyBytes, receiveKeyBytes) = kdf2(ck, ByteArray(0))
        // Initiator sends with the first key, receives with the second
        return KeyPair(Key(sendKeyBytes), Key(receiveKeyBytes.value), response.senderIndex)
    }
}

// --- Helper Data Classes and Utilities ---

data class HandshakeState(var chainingKey: ByteArray, var hash: ByteArray) {
    fun mixHash(data: ByteArray) { hash = hash(hash, data) }
    override fun equals(other: Any?) = other is HandshakeState && chainingKey.contentEquals(other.chainingKey) && hash.contentEquals(other.hash)
    override fun hashCode() = Arrays.deepHashCode(arrayOf(chainingKey, hash))
}

data class HandshakeSecrets(val chainingKey: ByteArray, val hash: ByteArray, val ephemeralPrivate: Key) {
    override fun equals(other: Any?) = other is HandshakeSecrets && chainingKey.contentEquals(other.chainingKey) && hash.contentEquals(other.hash) && ephemeralPrivate == other.ephemeralPrivate
    override fun hashCode() = Arrays.deepHashCode(arrayOf(chainingKey, hash, ephemeralPrivate))
}

class KeyPair(
    private val sendKey: Key,
    private val recvKey: Key,
    val remoteIndex: Int,
    val localIndex: Int = SecureRandom().nextInt(Int.MAX_VALUE),
    val createdAt: Long = System.currentTimeMillis()
) {
    private val txNonce = AtomicLong(0L)
    private val rxReplayFilter = ReplayFilter()
    @Volatile var lastPacketSentTimestamp: Long = 0
        private set

    fun encryptData(packet: ByteArray): DataMessage {
        val nonce = txNonce.getAndIncrement()
        val encrypted = Aead.chacha20Poly1305Encrypt(sendKey, nonce, packet, ByteArray(0))
        lastPacketSentTimestamp = System.currentTimeMillis()
        return DataMessage(remoteIndex, nonce, encrypted)
    }

    fun decryptData(message: DataMessage): ByteArray? {
        if (!rxReplayFilter.validate(message.counter)) return null
        return Aead.chacha20Poly1305Decrypt(recvKey, message.counter, message.encryptedData, ByteArray(0))
    }
}

class CookieGenerator(localStaticPublic: Key) {
    private val logger = org.slf4j.LoggerFactory.getLogger(CookieGenerator::class.java)
    private val lock = Any()
    @Volatile private var mac1Key: ByteArray = generateRandomKey()
    @Volatile private var mac2Key: ByteArray = generateRandomKey()
    @Volatile private var lastKeyRotation = System.currentTimeMillis()
    private val cookieKey = Key(hash(LABEL_COOKIE, localStaticPublic.value))

    private fun rotateKeysIfNeeded() = synchronized(lock) {
        if (System.currentTimeMillis() - lastKeyRotation > 120_000) {
            mac2Key = mac1Key
            mac1Key = generateRandomKey()
            lastKeyRotation = System.currentTimeMillis()
            logger.debug("Cookie MAC keys rotated.")
        }
    }

    fun createCookieReply(initiationMessage: HandshakeInitiationMessage, senderAddress: ByteArray): CookieReplyMessage {
        rotateKeysIfNeeded()
        val nonce = ByteArray(24).apply { SecureRandom().nextBytes(this) }
        val cookie = mac(mac1Key, senderAddress)
        val encryptedCookie = Aead.xchacha20Poly1305Encrypt(cookieKey, nonce, cookie, initiationMessage.mac1)
        return CookieReplyMessage(initiationMessage.senderIndex, nonce, encryptedCookie)
    }

    fun consumeCookie(initiationMessage: HandshakeInitiationMessage, senderAddress: ByteArray): Boolean {
        rotateKeysIfNeeded()
        if (initiationMessage.mac2.all { it == 0.toByte() }) return false
        val expectedCookie1 = mac(mac1Key, senderAddress)
        val expectedMac2FromCookie1 = mac(expectedCookie1, initiationMessage.bytesForMacs())
        if (constantTimeEquals(initiationMessage.mac2, expectedMac2FromCookie1)) return true
        val expectedCookie2 = mac(mac2Key, senderAddress)
        val expectedMac2FromCookie2 = mac(expectedCookie2, initiationMessage.bytesForMacs())
        return constantTimeEquals(initiationMessage.mac2, expectedMac2FromCookie2)
    }

    private fun generateRandomKey() = ByteArray(32).apply { SecureRandom().nextBytes(this) }
}

class ReplayFilter {
    private val lock = Any()
    private var latest: Long = -1
    private var window = 0UL

    fun validate(value: Long): Boolean = synchronized(lock) {
        if (value < 0) return false
        if (latest < 0) {
            latest = value
            return true
        }
        if (value > latest) {
            val shift = minOf(value - latest, 64)
            window = if (shift < 64) (window shl shift.toInt()) or (1UL shl (shift - 1).toInt()) else 1UL
            latest = value
            return true
        }
        val diff = latest - value
        if (diff >= 2000) return false
        val bit = 1UL shl diff.toInt().coerceAtMost(63)
        if ((window and bit) != 0UL) return false
        window = window or bit
        return true
    }

    fun validate(value: ByteArray): Boolean {
        if (value.size != 12) return false
        val seconds = ByteBuffer.wrap(value, 0, 8).order(ByteOrder.BIG_ENDIAN).long
        return validate(seconds)
    }
}

private fun tai64n(): ByteArray {
    val now = System.currentTimeMillis()
    val seconds = now / 1000 + 0x400000000000000aL
    val nanos = (now % 1000) * 1_000_000
    return ByteBuffer.allocate(12).order(ByteOrder.BIG_ENDIAN).putLong(seconds).putInt(nanos.toInt()).array()
}