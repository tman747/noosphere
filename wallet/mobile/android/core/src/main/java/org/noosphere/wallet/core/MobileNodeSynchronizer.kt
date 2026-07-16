package org.noosphere.wallet.core

import android.content.Context
import android.util.AtomicFile
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL

/** Public indexer in a configured control cluster used by the mobile quorum node. */
data class MobileNodeEndpoint(
    val baseUrl: String,
    val endpointId: String,
    val controlCluster: String,
)

/**
 * Durable state lives in noBackupFilesDir and is replaced through AtomicFile.
 * The Rust core verifies the chain binding, monotonic sequence, checkpoint
 * history, and checksum every time this state is opened.
 */
class MobileNodeStateStore(context: Context, fileName: String = "mindchain-light-node-v1.json") {
    private val file = AtomicFile(File(context.noBackupFilesDir, fileName))

    @Synchronized
    fun read(): String? {
        if (!file.baseFile.isFile) return null
        val bytes = file.openRead().use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            var total = 0
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                total += count
                if (total > MAX_STATE_BYTES) throw IOException("mobile_node_state_too_large")
                output.write(buffer, 0, count)
            }
            output.toByteArray()
        }
        return bytes.toString(Charsets.UTF_8)
    }

    @Synchronized
    fun write(value: String) {
        val bytes = value.toByteArray(Charsets.UTF_8)
        if (bytes.isEmpty() || bytes.size > MAX_STATE_BYTES) {
            throw IOException("mobile_node_state_too_large")
        }
        val output = file.startWrite()
        try {
            output.write(bytes)
            output.fd.sync()
            file.finishWrite(output)
        } catch (error: Exception) {
            file.failWrite(output)
            throw error
        }
    }

    companion object {
        private const val MAX_STATE_BYTES = 1_048_576
    }
}

/**
 * Bounded synchronous synchronization step. Invoke from WorkManager or another
 * background executor, never the main thread. Network transport supplies bytes;
 * all identity, quorum, ancestry, regression, and persistence decisions remain
 * in the shared Rust core.
 */
class MobileNodeSynchronizer(
    context: Context,
    chainId: String,
    genesisHash: String,
    maximumFreshnessMs: ULong,
    minimumControlClusterQuorum: UByte,
    endpoints: List<MobileNodeEndpoint>,
    private val store: MobileNodeStateStore = MobileNodeStateStore(context),
) : AutoCloseable {
    private val endpoints = endpoints.map(::validateEndpoint)
    private val node: MobileLightNode

    init {
        if (this.endpoints.size !in minimumControlClusterQuorum.toInt()..MAX_ENDPOINTS ||
            this.endpoints.map { it.baseUrl }.toSet().size != this.endpoints.size ||
            this.endpoints.map { it.endpointId }.toSet().size != this.endpoints.size
        ) {
            throw IllegalArgumentException("invalid_mobile_node_endpoints")
        }
        node = MobileLightNode(
            chainId = chainId,
            genesisHash = genesisHash,
            apiVersion = "v1",
            maximumFreshnessMs = maximumFreshnessMs,
            minimumControlClusterQuorum = minimumControlClusterQuorum,
            persistedStateJson = store.read(),
        )
    }

    fun snapshot(): MobileNodeSnapshot = node.snapshot()

    @Throws(IOException::class, WalletSdkException::class)
    fun synchronize(): MobileNodeSyncOutcome {
        val current = node.snapshot()
        val observations = endpoints.mapNotNull { endpoint ->
            try {
                val statusJson = getJson(endpoint.baseUrl + "/api/status")
                val ancestorHash = if (current.finalizedHeight == 0UL) {
                    null
                } else {
                    val block = JSONObject(
                        getJson(endpoint.baseUrl + "/api/v1/blocks/${current.finalizedHeight}"),
                    )
                    block.getString("hash")
                }
                EndpointStatusObservation(
                    endpointId = endpoint.endpointId,
                    controlCluster = endpoint.controlCluster,
                    statusJson = statusJson,
                    ancestorHash = ancestorHash,
                )
            } catch (_: IOException) {
                null
            } catch (_: RuntimeException) {
                null
            }
        }
        val outcome = node.observeFinalized(observations)
        store.write(outcome.persistedStateJson)
        return outcome
    }

    override fun close() {
        node.close()
    }

    private fun getJson(url: String): String {
        val connection = URL(url).openConnection() as? HttpURLConnection
            ?: throw IOException("mobile_node_transport_unavailable")
        try {
            connection.instanceFollowRedirects = false
            connection.requestMethod = "GET"
            connection.connectTimeout = CONNECT_TIMEOUT_MS
            connection.readTimeout = READ_TIMEOUT_MS
            connection.setRequestProperty("Accept", "application/vnd.noos.v1+json, application/json")
            connection.setRequestProperty("User-Agent", "MindChain-Mobile-Node/1")
            val status = connection.responseCode
            if (status != HttpURLConnection.HTTP_OK) {
                throw IOException("mobile_node_http_status_$status")
            }
            val contentType = connection.contentType?.substringBefore(';')?.trim()
            if (contentType != "application/json" && contentType != "application/vnd.noos.v1+json") {
                throw IOException("mobile_node_invalid_content_type")
            }
            val body = connection.inputStream.use { input ->
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                var total = 0
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    total += count
                    if (total > MAX_RESPONSE_BYTES) throw IOException("mobile_node_response_too_large")
                    output.write(buffer, 0, count)
                }
                output.toByteArray()
            }
            return body.toString(Charsets.UTF_8)
        } finally {
            connection.disconnect()
        }
    }

    companion object {
        private const val MAX_ENDPOINTS = 16
        private const val MAX_RESPONSE_BYTES = 1_048_576
        private const val CONNECT_TIMEOUT_MS = 10_000
        private const val READ_TIMEOUT_MS = 10_000

        private fun validateEndpoint(endpoint: MobileNodeEndpoint): MobileNodeEndpoint {
            val uri = try {
                URI(endpoint.baseUrl)
            } catch (error: Exception) {
                throw IllegalArgumentException("invalid_mobile_node_endpoint", error)
            }
            if (uri.scheme != "https" || uri.host.isNullOrEmpty() || uri.userInfo != null ||
                uri.query != null || uri.fragment != null || uri.path !in listOf("", "/") ||
                uri.port !in listOf(-1, 443) || !HASH64.matches(endpoint.endpointId) ||
                !HASH64.matches(endpoint.controlCluster)
            ) {
                throw IllegalArgumentException("invalid_mobile_node_endpoint")
            }
            return endpoint.copy(baseUrl = "https://${uri.host.lowercase()}")
        }

        private val HASH64 = Regex("^[0-9a-f]{64}$")
    }
}
