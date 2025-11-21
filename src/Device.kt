import com.google.common.base.Throwables
import com.sun.jna.LastErrorException
import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Structure
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.slf4j.LoggerFactory
import java.io.File
import java.io.IOException

// --- JNA Native Mappings ---
private interface CLibrary : Library {
    @Throws(LastErrorException::class)
    fun open(path: String, flags: Int): Int
    @Throws(LastErrorException::class)
    fun close(fd: Int): Int
    @Throws(LastErrorException::class)
    fun ioctl(fd: Int, request: Long, a: Any): Int
    @Throws(LastErrorException::class)
    fun read(fd: Int, buf: ByteArray, count: Long): Long
    @Throws(LastErrorException::class)
    fun write(fd: Int, buf: ByteArray, count: Long): Long

    companion object {
        val INSTANCE: CLibrary by lazy { Native.load("c", CLibrary::class.java) }
    }
}

@Structure.FieldOrder("ifr_name", "ifr_flags")
internal open class IfReq : Structure() {
    @JvmField var ifr_name = ByteArray(IFNAMSIZ)
    @JvmField var ifr_flags: Short = 0
    fun setName(name: String) {
        val nameBytes = name.toByteArray()
        System.arraycopy(nameBytes, 0, ifr_name, 0, nameBytes.size.coerceAtMost(IFNAMSIZ - 1))
    }
}

// --- Platform-Specific Constants ---
private const val IFNAMSIZ = 16
private const val O_RDWR = 0x0002
private const val IFF_TUN_LINUX = 0x0001
private const val IFF_NO_PI_LINUX = 0x1000
private const val TUNSETIFF_LINUX = 0x400454caL

/**
 * Represents a TUN virtual network interface.
 */
interface TunDevice {
    val name: String
    suspend fun read(buffer: ByteArray): Int
    suspend fun write(data: ByteArray): Int
    fun up()
    fun down()
}

/**
 * A cross-platform implementation of TunDevice for Unix-like systems.
 */
class UnixTunDevice(override val name: String, private val config: InterfaceConfig) : TunDevice {
    private val logger = LoggerFactory.getLogger(UnixTunDevice::class.java)
    private val osName = System.getProperty("os.name").lowercase()
    private var nativeFileDescriptor: Int = -1
    private var isUp = false
    private var actualInterfaceName: String = name

    init {
        logger.info("Preparing TUN device '$name' on OS: $osName")
        createDevice()
    }

    private fun createDevice() {
        try {
            when {
                osName.contains("linux") -> createLinuxTun()
                osName.contains("mac") || osName.contains("darwin") -> createMacOsTun()
                else -> throw UnsupportedOperationException("Unsupported OS: $osName")
            }
        } catch (e: Exception) {
            logger.error("Fatal error creating TUN device '$name'. Please ensure you have necessary permissions (e.g., run as root).", e)
            down() // Attempt cleanup
            throw e
        }
    }

    private fun createLinuxTun() {
        nativeFileDescriptor = CLibrary.INSTANCE.open("/dev/net/tun", O_RDWR)
        if (nativeFileDescriptor < 0) throw IOException("Failed to open /dev/net/tun. Error: ${Native.getLastError()}")
        val ifr = IfReq().apply {
            setName(name)
            ifr_flags = (IFF_TUN_LINUX or IFF_NO_PI_LINUX).toShort()
        }
        if (CLibrary.INSTANCE.ioctl(nativeFileDescriptor, TUNSETIFF_LINUX, ifr) < 0) {
            throw IOException("Failed to configure interface '$name' via ioctl. Error: ${Native.getLastError()}")
        }
        logger.info("Successfully created and configured Linux TUN device '$name'. FD: $nativeFileDescriptor")
    }

    private fun createMacOsTun() {
        for (i in 0..255) {
            val fd = CLibrary.INSTANCE.open("/dev/utun$i", O_RDWR)
            if (fd >= 0) {
                nativeFileDescriptor = fd
                actualInterfaceName = "utun$i"
                logger.info("Successfully opened macOS TUN device '$actualInterfaceName'. FD: $nativeFileDescriptor")
                return
            }
        }
        throw IOException("Could not find an available utun device on macOS.")
    }

    override suspend fun read(buffer: ByteArray): Int = withContext(Dispatchers.IO) {
        if (nativeFileDescriptor < 0) return@withContext -1
        try {
            val bytesRead = CLibrary.INSTANCE.read(nativeFileDescriptor, buffer, buffer.size.toLong())
            if (bytesRead < 0) {
                logger.error("Native read from '$actualInterfaceName' failed with error code: ${Native.getLastError()}")
                -1
            } else bytesRead.toInt()
        } catch (e: LastErrorException) {
            logger.error("Exception during native read from '$actualInterfaceName'", e)
            -1
        }
    }

    override suspend fun write(data: ByteArray): Int = withContext(Dispatchers.IO) {
        if (nativeFileDescriptor < 0) return@withContext -1
        try {
            val packetToWrite = if (osName.contains("mac") || osName.contains("darwin")) {
                val header = when (data[0].toInt() shr 4) {
                    4 -> byteArrayOf(0, 0, 0, 2)  // AF_INET
                    6 -> byteArrayOf(0, 0, 0, 30) // AF_INET6
                    else -> throw IOException("Invalid IP packet version")
                }
                header + data
            } else data
            val bytesWritten = CLibrary.INSTANCE.write(nativeFileDescriptor, packetToWrite, packetToWrite.size.toLong())
            if (bytesWritten < 0) {
                logger.error("Native write to '$actualInterfaceName' failed with error code: ${Native.getLastError()}")
                -1
            } else bytesWritten.toInt()
        } catch (e: LastErrorException) {
            logger.error("Exception during native write to '$actualInterfaceName'", e)
            -1
        }
    }

    override fun up() {
        if (isUp) return logger.info("Device '$actualInterfaceName' is already up.")
        logger.info("Bringing up device '$actualInterfaceName' and configuring routes/DNS...")
        try {
            config.addresses.forEach { executeCommand("ip address add ${it.address.hostAddress}/${it.prefix} dev $actualInterfaceName") }
            executeCommand("ip link set dev $actualInterfaceName mtu ${config.mtu}")
            executeCommand("ip link set dev $actualInterfaceName up")

            if (config.dnsServers.isNotEmpty()) {
                backupResolvConf()
                val dnsContent = config.dnsServers.joinToString("\n") { "nameserver ${it.hostAddress}" }
                File("/etc/resolv.conf").writeText(dnsContent)
            }
            config.postUp.forEach { executeCommand(it.replace("%i", actualInterfaceName)) }
            logger.info("Device '$actualInterfaceName' is now UP.")
            isUp = true
        } catch (e: Exception) {
            logger.error("Failed to bring up device '$actualInterfaceName'. Attempting to clean up.", e)
            down()
            throw e // Propagate the exception
        }
    }

    override fun down() {
        logger.info("Bringing down device '$actualInterfaceName'...")
        restoreResolvConf()
        if (isUp) {
            config.postDown.forEach { executeCommand(it, suppressErrors = true) }
        }
        if (nativeFileDescriptor != -1) {
            try {
                CLibrary.INSTANCE.close(nativeFileDescriptor)
                logger.info("Closed native file descriptor $nativeFileDescriptor")
            } catch (e: Exception) {
                logger.warn("Failed to close native file descriptor $nativeFileDescriptor", e)
            }
            nativeFileDescriptor = -1
        }
        if (isUp && osName.contains("linux")) {
            executeCommand("ip link del dev $actualInterfaceName", suppressErrors = true)
        }
        isUp = false
        logger.info("Device '$actualInterfaceName' is now DOWN.")
    }

    // --- FIX: Improved command execution with better error handling ---
    private fun executeCommand(command: String, suppressErrors: Boolean = false) {
        try {
            logger.info("Executing: '$command'")
            val process = ProcessBuilder("/bin/sh", "-c", command).redirectErrorStream(true).start()
            val output = process.inputStream.bufferedReader().readText()
            val exitCode = process.waitFor()
            if (exitCode != 0) {
                val message = "Command '$command' failed with exit code $exitCode. Output:\n$output"
                if (suppressErrors) logger.warn(message) else throw IOException(message)
            } else if (output.isNotBlank()) {
                logger.debug("Command '$command' output:\n$output")
            }
        } catch (e: Exception) {
            val message = "Failed to execute command '$command'"
            if (suppressErrors) logger.error(message, e) else throw IOException(message, e)
        }
    }

    private fun backupResolvConf() {
        val original = File("/etc/resolv.conf")
        val backup = File("/etc/resolv.conf.wgbackup")
        if (original.exists() && !backup.exists()) {
            original.copyTo(backup)
            logger.info("Backed up /etc/resolv.conf")
        }
    }

    private fun restoreResolvConf() {
        val original = File("/etc/resolv.conf")
        val backup = File("/etc/resolv.conf.wgbackup")
        if (backup.exists()) {
            backup.copyTo(original, overwrite = true)
            backup.delete()
            logger.info("Restored /etc/resolv.conf from backup.")
        }
    }
}