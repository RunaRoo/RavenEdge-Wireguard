import kotlinx.coroutines.*
import org.slf4j.LoggerFactory
import java.io.File
import kotlin.system.exitProcess

/**
 * Main entry point for the WireGuard VPN application.
 */
fun main(args: Array<String>) = runBlocking {
    val logger = LoggerFactory.getLogger("MainRavenEdge")
    logger.info("========================================================")
    logger.info("= Starting WireGuard-Kotlin Server")
    logger.info("= Version: 2.5 Alpha")
    logger.info("========================================================")

    // Use wg0.conf as default config file if none is provided
    val configFile = if (args.isNotEmpty()) args[0] else "wg0.conf"
    val configFileFile = File(configFile)
    if (!configFileFile.exists()) {
        logger.error("Configuration file not found at '$configFile'.")
        logger.error("Usage: java -jar wireguard.jar [path/to/your-config.conf]")
        exitProcess(1)
    }
    logger.info("Using configuration file: $configFile")

    val interfaceName = configFileFile.nameWithoutExtension

    var device: TunDevice? = null
    var node: Node? = null

    try {
        // Parse configuration file
        val (ifaceConfig, peerConfigs) = Config.parse(configFile)

        // Initialize and bring up the TUN device
        device = UnixTunDevice(interfaceName, ifaceConfig)
        device.up()

        // Create and start the core WireGuard node
        node = Node(ifaceConfig, peerConfigs, device)

        // Add a shutdown hook to gracefully stop the node on CTRL+C or system shutdown.
        Runtime.getRuntime().addShutdownHook(
            Thread {
                logger.info("Shutdown signal received. Stopping WireGuard node...")
                runBlocking { node?.stop() }
                logger.info("WireGuard node shutdown procedures complete.")
            }
        )

        // node.start() will suspend until the node's scope is cancelled.
        node.start()
    } catch (e: Exception) {
        // A CancellationException is expected on normal shutdown, so we don't log it as an error.
        if (e !is CancellationException) {
            logger.error("A critical error has forced the node to stop.", e)
        }
    } finally {
        logger.info("Cleaning up TUN device...")
        device?.down()
        logger.info("Application has shut down.")
    }
}