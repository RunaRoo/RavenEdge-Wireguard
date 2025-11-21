import io.netty.bootstrap.Bootstrap
import io.netty.buffer.Unpooled
import io.netty.channel.*
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.channel.socket.DatagramPacket
import io.netty.channel.socket.nio.NioDatagramChannel
import kotlinx.coroutines.*
import org.slf4j.LoggerFactory
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap

class Node(
    private val ifaceConfig: InterfaceConfig,
    peerConfigs: List<PeerConfig>,
    private val device: TunDevice
) {
    private val logger = LoggerFactory.getLogger(Node::class.java)
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val eventLoopGroup = NioEventLoopGroup()
    private var channel: Channel? = null

    private val peersByPublicKey = ConcurrentHashMap<Key, Peer>()
    private val peersBySessionId = ConcurrentHashMap<Int, Peer>()
    private val routingTable = RoutingTable<Peer>()
    private val secureRandom = SecureRandom()

    private val serverPrivateKey = Key.fromBase64(ifaceConfig.privateKey)
    private val serverPublicKey = privateToPublicKey(serverPrivateKey)
    val cookieGenerator = CookieGenerator(serverPublicKey)

    init {
        logger.info("Initializing Node with public key: ${serverPublicKey.toBase64()}")
        peerConfigs.forEach { peerConfig ->
            val peerPublicKey = Key.fromBase64(peerConfig.publicKey)
            val peer = Peer(scope, this, serverPrivateKey, serverPublicKey, peerConfig, ::sendUdpPacket, device::write)
            peersByPublicKey[peerPublicKey] = peer
            peerConfig.allowedIPs.forEach { cidr ->
                routingTable.insert(cidr, peer)
                logger.debug("Adding route: $cidr -> Peer ${peerPublicKey.toBase64().take(8)}")
            }
        }
        logger.info("Initialized ${peersByPublicKey.size} peers and ${routingTable.size()} routes.")
    }

    suspend fun start() {
        logger.info("WireGuard node starting...")
        startUdpServer()
        startTunReader()
        startPeerTimers()
        val port = (channel?.localAddress() as? InetSocketAddress)?.port ?: "N/A"
        logger.info("WireGuard node started successfully on ${device.name} listening at UDP port $port.")
        scope.coroutineContext[Job]?.join()
    }

    suspend fun stop() {
        logger.info("Stopping WireGuard node...")
        scope.cancel()
        channel?.close()?.awaitUninterruptibly()
        eventLoopGroup.shutdownGracefully().awaitUninterruptibly()
        logger.info("WireGuard node stopped.")
    }

    private fun startUdpServer() {
        val bootstrap = Bootstrap()
            .group(eventLoopGroup)
            .channel(NioDatagramChannel::class.java)
            .handler(object : SimpleChannelInboundHandler<DatagramPacket>() {
                override fun channelRead0(ctx: ChannelHandlerContext, msg: DatagramPacket) {
                    val data = ByteArray(msg.content().readableBytes())
                    msg.content().readBytes(data)
                    scope.launch { handleUdpPacket(data, msg.sender()) }
                }
                override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
                    logger.warn("Netty UDP exception", cause)
                }
            })
        try {
            val listenPort = ifaceConfig.listenPort ?: 0
            val boundChannel = bootstrap.bind(listenPort).sync().channel()
            this.channel = boundChannel
            logger.info("UDP server listening on port ${(boundChannel.localAddress() as InetSocketAddress).port}")
        } catch (e: Exception) {
            logger.error("Failed to bind to UDP port ${ifaceConfig.listenPort}. Is it in use?", e)
            throw e
        }
    }

    private fun startTunReader() = scope.launch {
        logger.info("TUN device reader started on ${device.name}.")
        val buffer = ByteArray(ifaceConfig.mtu + 200)
        while (isActive) {
            try {
                val readBytes = device.read(buffer)
                if (readBytes > 0) {
                    val packet = buffer.sliceArray(0 until readBytes)
                    handleTunPacket(packet)
                }
            } catch (e: Exception) {
                if (e is CancellationException) break
                logger.error("Error reading from TUN device", e)
                delay(100)
            }
        }
        logger.warn("TUN device reader stopped.")
    }

    private fun startPeerTimers() = scope.launch {
        while (isActive) {
            delay(1000)
            peersByPublicKey.values.forEach { it.tick() }
        }
    }

    private suspend fun handleUdpPacket(data: ByteArray, sender: InetSocketAddress) {
        if (data.isEmpty()) return
        when (MessageType.from(data[0])) {
            MessageType.HANDSHAKE_INITIATION -> handleHandshakeInitiation(data, sender)
            MessageType.DATA -> {
                if (data.size < 16) return logger.warn("Runt data packet from $sender")
                val receiverIndex = ByteBuffer.wrap(data, 4, 4).order(ByteOrder.LITTLE_ENDIAN).int
                peersBySessionId[receiverIndex]?.onUdpPacket(DataMessage.fromBytes(data), sender)
            }
            else -> logger.warn("Received unexpected/unknown packet type ${data.getOrNull(0)} from $sender")
        }
    }

    private suspend fun handleHandshakeInitiation(data: ByteArray, sender: InetSocketAddress) {
        if (data.size < 148) return logger.warn("Runt handshake initiation from $sender")
        val msg = HandshakeInitiationMessage.fromBytes(data)

        val mac1Key = hash(LABEL_MAC1, serverPublicKey.value)
        if (!constantTimeEquals(mac(mac1Key, msg.bytesForMacs()), msg.mac1)) {
            return logger.warn("Invalid mac1 on handshake initiation from $sender. Discarding.")
        }

        val peer = findPeerFromInitiation(msg)
        if (peer == null) {
            // The detailed log message is now inside findPeerFromInitiation
            return
        }

        logger.debug("Handshake initiation from $sender has a valid mac1 and has been identified as Peer ${peer.publicKey.toBase64().take(8)}")
        peer.onUdpPacket(msg, sender)
    }

    private fun findPeerFromInitiation(msg: HandshakeInitiationMessage): Peer? {
        var chainingKey = hash(PROTOCOL_NAME)
        var currentHash = hash(chainingKey, IDENTIFIER)
        currentHash = hash(currentHash, serverPublicKey.value)
        currentHash = hash(currentHash, msg.unencryptedEphemeral.value)

        // This KDF1 step was previously missing.
        chainingKey = kdf1(chainingKey, msg.unencryptedEphemeral.value)

        val sharedSecret = x25519(serverPrivateKey, msg.unencryptedEphemeral)
        val (ck, key) = kdf2(chainingKey, sharedSecret)

        val decryptedStatic = Aead.chacha20Poly1305Decrypt(key, 0, msg.encryptedStatic, currentHash)

        if (decryptedStatic == null) {
            logger.warn("AEAD decryption of static key failed for handshake from an unknown peer.")
            return null
        }

        val peerKey = Key(decryptedStatic)
        val peer = peersByPublicKey[peerKey]
        if (peer == null) {
            logger.warn("Successfully decrypted static key ${peerKey.toBase64()}, but no peer is configured with this public key.")
        }
        return peer
    }

    private suspend fun handleTunPacket(packet: ByteArray) {
        val destinationAddress = getDestinationAddress(packet) ?: return logger.warn("Could not parse destination IP from TUN packet.")
        val peer = routingTable.findBestMatch(destinationAddress)
        if (peer == null) return
        peer.onTunPacket(packet)
    }

    private fun sendUdpPacket(data: ByteArray, destination: InetSocketAddress) {
        channel?.writeAndFlush(DatagramPacket(Unpooled.wrappedBuffer(data), destination))
    }

    fun registerSession(peer: Peer, keyPair: KeyPair) {
        logger.info("Registering new session ${keyPair.localIndex} for peer ${peer.publicKey.toBase64().take(8)}")
        peersBySessionId[keyPair.localIndex] = peer
    }

    fun removeSession(sessionId: Int) {
        logger.info("Removing session $sessionId")
        peersBySessionId.remove(sessionId)
    }

    fun findAvailableIndex(): Int {
        while (true) {
            val index = secureRandom.nextInt(Int.MAX_VALUE)
            if (peersBySessionId.putIfAbsent(index, PeerDUMMY) == null) return index
        }
    }

    private fun getDestinationAddress(packet: ByteArray): InetAddress? {
        if (packet.isEmpty()) return null
        return try {
            when (packet[0].toInt() shr 4) {
                4 -> if (packet.size >= 20) Inet4Address.getByAddress(packet.sliceArray(16..19)) else null
                6 -> if (packet.size >= 40) Inet6Address.getByAddress(packet.sliceArray(24..39)) else null
                else -> null
            }
        } catch (e: Exception) { null }
    }

    private val PeerDUMMY: Peer by lazy {
        val dummyPeerConfig = PeerConfig("", null, emptyList(), null, null)
        Peer(scope, this, serverPrivateKey, serverPublicKey, dummyPeerConfig, { _, _ -> }, {})
    }
}