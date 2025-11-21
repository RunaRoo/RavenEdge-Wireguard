import org.apache.commons.collections4.trie.PatriciaTrie
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

/**
 * A high-performance, thread-safe routing table for WireGuard peers.
 * This implementation uses two Patricia Tries (one for IPv4, one for IPv6)
 * to provide fast, longest-prefix matching of IP addresses.
 *
 * --- FIX: Replaced @Synchronized with a more granular ReadWriteLock ---
 * This allows multiple concurrent reads, significantly improving performance
 * under load, as lookups are far more common than route modifications.
 */
class RoutingTable<T> {
    private val ipv4Routes = PatriciaTrie<T>()
    private val ipv6Routes = PatriciaTrie<T>()
    private val lock = ReentrantReadWriteLock()

    fun insert(cidr: CIDR, value: T) = lock.write {
        val key = cidr.toBitString()
        when (cidr.address) {
            is Inet4Address -> ipv4Routes[key] = value
            is Inet6Address -> ipv6Routes[key] = value
        }
    }

    fun remove(cidr: CIDR) = lock.write {
        val key = cidr.toBitString()
        when (cidr.address) {
            is Inet4Address -> ipv4Routes.remove(key)
            is Inet6Address -> ipv6Routes.remove(key)
        }
    }

    fun findBestMatch(address: InetAddress): T? = lock.read {
        val key = address.toBitString()
        val trie = when (address) {
            is Inet4Address -> ipv4Routes
            is Inet6Address -> ipv6Routes
            else -> return null // Unsupported address family
        }
        // selectKey performs the longest-prefix match in the trie
        val bestMatchPrefix = trie.selectKey(key) ?: return null
        return trie[bestMatchPrefix]
    }

    fun clear() = lock.write {
        ipv4Routes.clear()
        ipv6Routes.clear()
    }

    fun size(): Int = lock.read { ipv4Routes.size + ipv6Routes.size }
}

/**
 * Represents a CIDR address with utility functions for trie-based routing.
 */
data class CIDR(val address: InetAddress, val prefix: Int) {
    /**
     * Converts the CIDR network prefix to a bit string for use as a trie key.
     */
    fun toBitString(): String = address.toBitString().take(prefix)

    companion object {
        fun fromString(cidr: String): CIDR {
            val parts = cidr.split('/')
            require(parts.size == 2) { "Invalid CIDR format: $cidr" }
            val address = InetAddress.getByName(parts[0])
            val prefix = parts[1].toInt()
            val maxPrefix = if (address is Inet4Address) 32 else 128
            require(prefix in 0..maxPrefix) { "Invalid prefix length for $cidr" }
            return CIDR(address, prefix)
        }
    }
}

/**
 * Extension function to convert any InetAddress to its full binary string representation.
 */
private fun InetAddress.toBitString(): String =
    this.address.joinToString("") { byte ->
        byte.toUByte().toString(2).padStart(8, '0')
    }