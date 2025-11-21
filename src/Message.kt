import com.google.common.primitives.Bytes
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Arrays

// --- FIX: This enum is now complete and used for type checking ---
enum class MessageType(val id: Byte) {
    HANDSHAKE_INITIATION(1),
    HANDSHAKE_RESPONSE(2),
    COOKIE_REPLY(3),
    DATA(4);

    companion object {
        fun from(id: Byte): MessageType? = entries.find { it.id == id }
    }
}

interface Message {
    val type: MessageType
    fun toBytes(): ByteArray
}

/**
 * --- FIX: All multi-byte fields are serialized using a ByteBuffer set to LITTLE_ENDIAN. ---
 * This is the most robust way to ensure protocol compliance across all platforms.
 */
data class HandshakeInitiationMessage(
    val senderIndex: Int,
    val unencryptedEphemeral: Key,
    var encryptedStatic: ByteArray,    // 32 bytes + 16 tag = 48 bytes
    var encryptedTimestamp: ByteArray, // 12 bytes + 16 tag = 28 bytes
    var mac1: ByteArray,
    var mac2: ByteArray
) : Message {
    override val type = MessageType.HANDSHAKE_INITIATION

    override fun toBytes(): ByteArray {
        val buf = ByteBuffer.allocate(148).order(ByteOrder.LITTLE_ENDIAN)
        buf.put(type.id).put(ByteArray(3)) // type + reserved
        buf.putInt(senderIndex)
        buf.put(unencryptedEphemeral.value)
        buf.put(encryptedStatic)
        buf.put(encryptedTimestamp)
        buf.put(mac1)
        buf.put(mac2)
        return buf.array()
    }

    fun bytesForMacs(): ByteArray = toBytes().sliceArray(0 until (148 - 32))

    override fun equals(other: Any?) = other is HandshakeInitiationMessage &&
            senderIndex == other.senderIndex && unencryptedEphemeral == other.unencryptedEphemeral &&
            encryptedStatic.contentEquals(other.encryptedStatic) &&
            encryptedTimestamp.contentEquals(other.encryptedTimestamp) &&
            mac1.contentEquals(other.mac1) && mac2.contentEquals(other.mac2)

    override fun hashCode() = Arrays.deepHashCode(arrayOf(senderIndex, unencryptedEphemeral, encryptedStatic, encryptedTimestamp, mac1, mac2))
    //todo replaced with Kotlin function below, keep an eye on it, it may lead to silent errors (Now reverted back)
    //override fun hashCode() = arrayOf(
    //   senderIndex,
    //    unencryptedEphemeral,
    //    encryptedStatic,
    //    encryptedTimestamp,
    //    mac1,
    //    mac2
    //).contentDeepHashCode()

    companion object {
        fun fromBytes(bytes: ByteArray): HandshakeInitiationMessage {
            require(bytes.size >= 148) { "Invalid handshake initiation size" }
            val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            buf.position(4) // Skip type and reserved fields
            return HandshakeInitiationMessage(
                senderIndex = buf.int,
                unencryptedEphemeral = Key(ByteArray(KEY_LENGTH).also { buf.get(it) }),
                encryptedStatic = ByteArray(48).also { buf.get(it) },
                encryptedTimestamp = ByteArray(28).also { buf.get(it) },
                mac1 = ByteArray(16).also { buf.get(it) },
                mac2 = ByteArray(16).also { buf.get(it) }
            )
        }
    }
}

data class HandshakeResponseMessage(
    val senderIndex: Int,
    val receiverIndex: Int,
    val unencryptedEphemeral: Key,
    val encryptedNothing: ByteArray, // 0 bytes + 16 tag = 16 bytes
    var mac1: ByteArray,
    var mac2: ByteArray
) : Message {
    override val type = MessageType.HANDSHAKE_RESPONSE

    override fun toBytes(): ByteArray {
        val buf = ByteBuffer.allocate(92).order(ByteOrder.LITTLE_ENDIAN)
        buf.put(type.id).put(ByteArray(3))
        buf.putInt(senderIndex)
        buf.putInt(receiverIndex)
        buf.put(unencryptedEphemeral.value)
        buf.put(encryptedNothing)
        buf.put(mac1)
        buf.put(mac2)
        return buf.array()
    }

    fun bytesForMacs(): ByteArray = toBytes().sliceArray(0 until (92 - 32))

    override fun equals(other: Any?) = other is HandshakeResponseMessage &&
            senderIndex == other.senderIndex && receiverIndex == other.receiverIndex &&
            unencryptedEphemeral == other.unencryptedEphemeral &&
            encryptedNothing.contentEquals(other.encryptedNothing) && mac1.contentEquals(other.mac1) &&
            mac2.contentEquals(other.mac2)

    override fun hashCode() = Arrays.deepHashCode(arrayOf(senderIndex, receiverIndex, unencryptedEphemeral, encryptedNothing, mac1, mac2))

    companion object {
        fun fromBytes(bytes: ByteArray): HandshakeResponseMessage {
            require(bytes.size >= 92) { "Invalid handshake response size" }
            val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            buf.position(4)
            return HandshakeResponseMessage(
                senderIndex = buf.int, receiverIndex = buf.int,
                unencryptedEphemeral = Key(ByteArray(KEY_LENGTH).also { buf.get(it) }),
                encryptedNothing = ByteArray(16).also { buf.get(it) },
                mac1 = ByteArray(16).also { buf.get(it) }, mac2 = ByteArray(16).also { buf.get(it) }
            )
        }
    }
}

data class CookieReplyMessage(
    val receiverIndex: Int,
    val nonce: ByteArray,         // 24 bytes
    val encryptedCookie: ByteArray  // 16 bytes cookie + 16 tag = 32 bytes
) : Message {
    override val type = MessageType.COOKIE_REPLY
    override fun toBytes(): ByteArray {
        val buf = ByteBuffer.allocate(64).order(ByteOrder.LITTLE_ENDIAN)
        buf.put(type.id).put(ByteArray(3))
        buf.putInt(receiverIndex)
        buf.put(nonce)
        buf.put(encryptedCookie)
        return buf.array()
    }

    override fun equals(other: Any?) = other is CookieReplyMessage &&
            receiverIndex == other.receiverIndex && nonce.contentEquals(other.nonce) &&
            encryptedCookie.contentEquals(other.encryptedCookie)

    override fun hashCode() = Arrays.deepHashCode(arrayOf(receiverIndex, nonce, encryptedCookie))

    companion object {
        fun fromBytes(bytes: ByteArray): CookieReplyMessage {
            require(bytes.size >= 64) { "Invalid cookie reply size" }
            val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            buf.position(4)
            return CookieReplyMessage(
                receiverIndex = buf.int,
                nonce = ByteArray(24).apply { buf.get(this) },
                encryptedCookie = ByteArray(32).apply { buf.get(this) }
            )
        }
    }
}

data class DataMessage(
    val receiverIndex: Int,
    val counter: Long,
    val encryptedData: ByteArray
) : Message {
    override val type = MessageType.DATA
    override fun toBytes(): ByteArray = Bytes.concat(
        ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN)
            .put(type.id).put(ByteArray(3))
            .putInt(receiverIndex)
            .putLong(counter)
            .array(),
        encryptedData
    )

    override fun equals(other: Any?) = other is DataMessage &&
            receiverIndex == other.receiverIndex && counter == other.counter &&
            encryptedData.contentEquals(other.encryptedData)

    override fun hashCode() = arrayOf(receiverIndex, counter, encryptedData).contentDeepHashCode()

    companion object {
        fun fromBytes(bytes: ByteArray): DataMessage {
            require(bytes.size >= 16) { "Invalid data message size" }
            val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            buf.position(4)
            return DataMessage(
                receiverIndex = buf.int, counter = buf.long,
                encryptedData = ByteArray(bytes.size - 16).apply { buf.get(this) }
            )
        }
    }
}