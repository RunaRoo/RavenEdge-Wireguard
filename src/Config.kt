import com.google.common.base.Preconditions
import com.google.common.net.HostAndPort
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress

data class InterfaceConfig(
    val privateKey: String,
    val addresses: List<CIDR>,
    val listenPort: Int?,
    val dnsServers: List<InetAddress>,
    val postUp: List<String>,
    val postDown: List<String>,
    val mtu: Int
)

data class PeerConfig(
    val publicKey: String,
    val presharedKey: String?,
    val allowedIPs: List<CIDR>,
    val endpoint: InetSocketAddress?,
    val persistentKeepalive: Int?
)

object Config {
    fun parse(filePath: String): Pair<InterfaceConfig, List<PeerConfig>> {
        val lines = File(filePath).readLines()
        val interfaceProps = mutableMapOf<String, MutableList<String>>()
        val peerPropsList = mutableListOf<MutableMap<String, MutableList<String>>>()

        var currentProps: MutableMap<String, MutableList<String>>? = null

        for (line in lines) {
            val trimmedLine = line.trim()
            if (trimmedLine.isBlank() || trimmedLine.startsWith('#')) continue

            when {
                trimmedLine.equals("[Interface]", ignoreCase = true) -> {
                    currentProps = interfaceProps
                }
                trimmedLine.equals("[Peer]", ignoreCase = true) -> {
                    currentProps = mutableMapOf<String, MutableList<String>>().also { peerPropsList.add(it) }
                }
                trimmedLine.contains('=') && currentProps != null -> {
                    val (key, value) = trimmedLine.split('=', limit = 2).map { it.trim() }
                    currentProps.computeIfAbsent(key.lowercase()) { mutableListOf() }.add(value)
                }
            }
        }

        // --- FIX: Using Guava's Preconditions for robust validation ---
        val privateKey = interfaceProps["privatekey"]?.first()
        Preconditions.checkArgument(privateKey != null, "PrivateKey missing in Interface section")

        val ifaceConfig = InterfaceConfig(
            privateKey = privateKey!!,
            addresses = interfaceProps["address"]?.flatMap { it.split(',').map { s -> CIDR.fromString(s.trim()) } } ?: emptyList(),
            listenPort = interfaceProps["listenport"]?.firstOrNull()?.toInt(),
            dnsServers = interfaceProps["dns"]?.flatMap { it.split(',').map { s -> InetAddress.getByName(s.trim()) } } ?: emptyList(),
            postUp = interfaceProps["postup"] ?: emptyList(),
            postDown = interfaceProps["postdown"] ?: emptyList(),
            mtu = interfaceProps["mtu"]?.firstOrNull()?.toInt() ?: 1420
        )

        val peerConfigs = peerPropsList.map { props ->
            val publicKey = props["publickey"]?.first()
            Preconditions.checkArgument(publicKey != null, "PublicKey missing in a Peer section")

            PeerConfig(
                publicKey = publicKey!!,
                presharedKey = props["presharedkey"]?.firstOrNull(),
                allowedIPs = props["allowedips"]?.flatMap { it.split(',').map { ip -> CIDR.fromString(ip.trim()) } } ?: emptyList(),
                // --- FIX: Using Guava's HostAndPort for robust endpoint parsing ---
                endpoint = props["endpoint"]?.firstOrNull()?.let {
                    val hostAndPort = HostAndPort.fromString(it)
                    InetSocketAddress(hostAndPort.host, hostAndPort.port)
                },
                persistentKeepalive = props["persistentkeepalive"]?.firstOrNull()?.toInt()
            )
        }

        return Pair(ifaceConfig, peerConfigs)
    }
}