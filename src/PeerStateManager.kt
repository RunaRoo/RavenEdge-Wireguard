import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import org.slf4j.LoggerFactory
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicBoolean

class Peer(
    private val scope: CoroutineScope,
    private val node: Node,
    private val localStaticPrivate: Key,
    private val localStaticPublic: Key,
    private val peerConfig: PeerConfig,
    private val udpSender: (ByteArray, InetSocketAddress) -> Unit,
    private val tunWriter: suspend (ByteArray) -> Unit
) {
    val publicKey: Key = Key.fromBase64(peerConfig.publicKey)
    private val logger = LoggerFactory.getLogger("Peer-${publicKey.toBase64().take(8)}")

    @Volatile
    var endpoint: InetSocketAddress? = peerConfig.endpoint
    @Volatile
    private var lastPacketReceivedTimestamp: Long = 0

    private val noise = Noise(localStaticPrivate, localStaticPublic, publicKey, peerConfig.presharedKey?.let { Key.fromBase64(it) })
    private val handshakeTimestampFilter = ReplayFilter()

    @Volatile
    private var currentKeyPair: KeyPair? = null
    @Volatile
    private var nextKeyPair: KeyPair? = null

    private var handshakeSecrets: HandshakeSecrets? = null
    private val handshakeInProgress = AtomicBoolean(false)
    private var lastHandshakeSentTimestamp: Long = 0
    private var lastInitiationMessage: HandshakeInitiationMessage? = null

    @OptIn(ExperimentalCoroutinesApi::class)
    private val packetQueue = Channel<ByteArray>(Channel.BUFFERED)

    private val REKEY_AFTER_TIME_MS = 120_000L
    private val REJECT_AFTER_TIME_MS = 180_000L
    private val KEEPALIVE_TIMEOUT_MS = peerConfig.persistentKeepalive?.let { it * 1000L } ?: 25_000L
    private val HANDSHAKE_TIMEOUT_MS = 5_000L
    private val REKEY_ATTEMPT_TIME_MS = 90_000L

    init {
        logger.info("Initialized for endpoint ${endpoint ?: "unknown"}")
        if (peerConfig.endpoint != null) {
            logger.info("Endpoint is pre-configured. This peer will act as an initiator (client).")
            scope.launch { initiateHandshake() }
        }
    }

    suspend fun tick() {
        if (shouldInitiateHandshake()) initiateHandshake()
        if (shouldSendKeepalive()) sendKeepalive()
        currentKeyPair?.let {
            if (System.currentTimeMillis() - it.createdAt > REJECT_AFTER_TIME_MS) {
                logger.warn("Current keypair expired after $REJECT_AFTER_TIME_MS ms, clearing.")
                currentKeyPair = null
            }
        }
    }

    suspend fun onUdpPacket(message: Message, sender: InetSocketAddress) {
        if (endpoint != sender) {
            logger.info("Peer endpoint has roamed from $endpoint to $sender")
            endpoint = sender
        }
        lastPacketReceivedTimestamp = System.currentTimeMillis()
        when (message) {
            is HandshakeInitiationMessage -> onHandshakeInitiation(message, sender)
            is HandshakeResponseMessage -> onHandshakeResponse(message)
            is DataMessage -> onDataMessage(message)
            is CookieReplyMessage -> onCookieReply(message)
        }
    }

    suspend fun onTunPacket(packet: ByteArray) {
        val keyPair = currentKeyPair
        if (keyPair == null || (System.currentTimeMillis() - keyPair.createdAt > REKEY_AFTER_TIME_MS)) {
            if (!packetQueue.trySend(packet).isSuccess) logger.warn("Packet queue is full. Dropping outbound packet.")
            if (!handshakeInProgress.get()) initiateHandshake()
            return
        }
        val endpointAddr = endpoint ?: return
        val dataMessage = keyPair.encryptData(packet)
        udpSender(dataMessage.toBytes(), endpointAddr)
    }

    private suspend fun onHandshakeInitiation(msg: HandshakeInitiationMessage, sender: InetSocketAddress) {
        if (!node.cookieGenerator.consumeCookie(msg, sender.address.address)) {
            logger.warn("Handshake from $sender has invalid or missing cookie. Replying with cookie.")
            val cookieReply = node.cookieGenerator.createCookieReply(msg, sender.address.address)
            udpSender(cookieReply.toBytes(), sender)
            return
        }
        val (handshakeState, validationError) = validateAndDecryptInitiation(msg)
        if (validationError != null) {
            logger.warn("Failed to validate handshake initiation: $validationError")
            return
        }
        constructAndSendResponse(handshakeState!!, msg.senderIndex, msg.unencryptedEphemeral)
    }

    private suspend fun onHandshakeResponse(msg: HandshakeResponseMessage) {
        val secrets = handshakeSecrets ?: return
        val keyPair = noise.consumeHandshakeResponse(secrets, msg)
            ?: return logger.warn("Failed to consume handshake response.").also { handshakeInProgress.set(false) }
        node.registerSession(this, keyPair)
        nextKeyPair = keyPair
        rotateKeys()
        handshakeInProgress.set(false)
        logger.info("Completed handshake as initiator. Ready for data.")
    }

    private suspend fun onCookieReply(msg: CookieReplyMessage) {
        val lastInit = lastInitiationMessage ?: return
        if (msg.receiverIndex != lastInit.senderIndex) return
        logger.info("Received cookie reply, will resend handshake with cookie.")
        val decryptedCookie = Aead.xchacha20Poly1305Decrypt(
            key = Key(hash(LABEL_COOKIE + publicKey.value)),
            nonce = msg.nonce,
            ciphertext = msg.encryptedCookie,
            associatedData = lastInit.mac1
        )
        if (decryptedCookie != null) {
            initiateHandshake(decryptedCookie)
        } else {
            logger.warn("Could not decrypt cookie reply. Discarding.")
            handshakeInProgress.set(false)
        }
    }

    private suspend fun onDataMessage(msg: DataMessage) {
        val (keypair, decryptedData) = when {
            currentKeyPair?.remoteIndex == msg.receiverIndex -> currentKeyPair to currentKeyPair?.decryptData(msg)
            nextKeyPair?.remoteIndex == msg.receiverIndex -> nextKeyPair to nextKeyPair?.decryptData(msg)
            else -> null to null
        }
        if (decryptedData != null) {
            if (keypair == nextKeyPair) {
                logger.info("First data packet received on new session, rotating keys.")
                rotateKeys()
            }
            if (decryptedData.isNotEmpty()) tunWriter(decryptedData) else logger.debug("Received keepalive.")
        } else {
            logger.warn("Failed to decrypt data message from {}. Discarding.", endpoint)
        }
    }

    private fun validateAndDecryptInitiation(msg: HandshakeInitiationMessage): Pair<HandshakeState?, String?> {
        val state = HandshakeState(hash(PROTOCOL_NAME), hash(hash(PROTOCOL_NAME) + IDENTIFIER))
        state.mixHash(localStaticPublic.value)
        state.mixHash(msg.unencryptedEphemeral.value)

        val sharedSecret1 = x25519(localStaticPrivate, msg.unencryptedEphemeral)
        val (ck1, key1) = kdf2(state.chainingKey, sharedSecret1)
        state.chainingKey = ck1

        val decryptedStatic = Aead.chacha20Poly1305Decrypt(key1, 0, msg.encryptedStatic, state.hash)
            ?: return null to "Failed to decrypt static key"
        if (!constantTimeEquals(decryptedStatic, publicKey.value)) return null to "Decrypted static key mismatch"
        state.mixHash(msg.encryptedStatic)

        val sharedSecret2 = x25519(localStaticPrivate, publicKey)
        val (ck2, key2) = kdf2(state.chainingKey, sharedSecret2)
        state.chainingKey = ck2

        val timestamp = Aead.chacha20Poly1305Decrypt(key2, 0, msg.encryptedTimestamp, state.hash)
            ?: return null to "Failed to decrypt timestamp"
        if (!handshakeTimestampFilter.validate(timestamp)) return null to "Replayed or old timestamp"
        state.mixHash(msg.encryptedTimestamp)

        peerConfig.presharedKey?.let { psk ->
            val (ck3, tempHashKey, _) = kdf3(state.chainingKey, Key.fromBase64(psk).value)
            state.chainingKey = ck3
            state.mixHash(tempHashKey.value)
        }
        return state to null
    }

    private suspend fun constructAndSendResponse(state: HandshakeState, remoteIndex: Int, remoteEphemeral: Key) {
        val (ephemeralPrivate, ephemeralPublic) = generateKeyPair()
        state.mixHash(ephemeralPublic.value)
        state.chainingKey = kdf2(state.chainingKey, x25519(ephemeralPrivate, remoteEphemeral)).first
        state.chainingKey = kdf2(state.chainingKey, x25519(ephemeralPrivate, publicKey)).first

        peerConfig.presharedKey?.let { psk ->
            val (ck, tempKey, _) = kdf3(state.chainingKey, Key.fromBase64(psk).value)
            state.chainingKey = ck
            state.mixHash(tempKey.value)
        }

        val (ck, key) = kdf2(state.chainingKey, ByteArray(0))
        state.chainingKey = ck

        val encryptedNothing = Aead.chacha20Poly1305Encrypt(key, 0, ByteArray(0), state.hash)
        state.mixHash(encryptedNothing)

        val (sendKeyBytes, receiveKey) = kdf2(state.chainingKey, ByteArray(0))
        val newKeyPair = KeyPair(receiveKey, Key(sendKeyBytes), remoteIndex, node.findAvailableIndex())

        val response = HandshakeResponseMessage(
            newKeyPair.localIndex, remoteIndex, ephemeralPublic, encryptedNothing, ByteArray(16), ByteArray(16)
        )
        response.mac1 = mac(hash(LABEL_MAC1 + localStaticPublic.value), response.bytesForMacs())

        node.registerSession(this, newKeyPair)
        nextKeyPair = newKeyPair
        udpSender(response.toBytes(), endpoint!!)
        rotateKeys()
        logger.info("Completed handshake as responder. Ready for data.")
    }

    private fun shouldInitiateHandshake(): Boolean {
        if (handshakeInProgress.get() || endpoint == null) return false
        val keyPair = currentKeyPair
        return when {
            keyPair == null -> true
            System.currentTimeMillis() - keyPair.createdAt > REKEY_AFTER_TIME_MS -> true
            keyPair.lastPacketSentTimestamp > 0 && System.currentTimeMillis() - keyPair.lastPacketSentTimestamp > REKEY_ATTEMPT_TIME_MS -> true
            else -> false
        }
    }

    private fun shouldSendKeepalive(): Boolean {
        if (endpoint == null || currentKeyPair == null || KEEPALIVE_TIMEOUT_MS <= 0) return false
        val now = System.currentTimeMillis()
        if (now - lastPacketReceivedTimestamp < KEEPALIVE_TIMEOUT_MS) return false
        return now - (currentKeyPair?.lastPacketSentTimestamp ?: 0) > KEEPALIVE_TIMEOUT_MS
    }

    private suspend fun initiateHandshake(cookie: ByteArray? = null) {
        if (cookie == null && !handshakeInProgress.compareAndSet(false, true)) return
        val currentEndpoint = endpoint ?: return Unit.also { handshakeInProgress.set(false) }

        logger.info("Initiating handshake to $currentEndpoint ${if (cookie != null) "with cookie" else ""}")
        lastHandshakeSentTimestamp = System.currentTimeMillis()

        val (handshakeMessage, secrets) = noise.createHandshakeInitiation(node.findAvailableIndex())
        cookie?.let {
            handshakeMessage.mac2 = mac(it, handshakeMessage.bytesForMacs())
        }

        this.handshakeSecrets = secrets
        this.lastInitiationMessage = handshakeMessage
        udpSender(handshakeMessage.toBytes(), currentEndpoint)

        scope.launch {
            delay(HANDSHAKE_TIMEOUT_MS)
            if (handshakeInProgress.get() && System.currentTimeMillis() - lastHandshakeSentTimestamp >= HANDSHAKE_TIMEOUT_MS) {
                logger.warn("Handshake to $currentEndpoint timed out.")
                handshakeInProgress.set(false)
            }
        }
    }

    private fun sendKeepalive() {
        val keyPair = currentKeyPair ?: return
        val endpointAddr = endpoint ?: return
        logger.debug("Sending keepalive packet to {}", endpointAddr)
        val dataMessage = keyPair.encryptData(ByteArray(0))
        udpSender(dataMessage.toBytes(), endpointAddr)
    }

    private suspend fun rotateKeys() {
        currentKeyPair?.let { node.removeSession(it.localIndex) }
        currentKeyPair = nextKeyPair
        nextKeyPair = null
        logger.info("Keys rotated. New current session index: ${currentKeyPair?.localIndex}")
        flushPacketQueue()
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    private suspend fun flushPacketQueue() {
        val keyPair = currentKeyPair ?: return logger.warn("Cannot flush queue, no valid keypair.")
        val endpointAddr = endpoint ?: return logger.warn("Cannot flush queue, no valid endpoint.")
        var count = 0
        while (!packetQueue.isEmpty) {
            val packet = packetQueue.receive()
            udpSender(keyPair.encryptData(packet).toBytes(), endpointAddr)
            count++
        }
        if (count > 0) logger.info("Flushed $count packets from queue.")
    }
}