package org.noosphere.wallet.core

import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

/** Status and unspent-note material accepted from configured indexer control clusters. */
data class WalletTransferBundle(
    val statusJson: String,
    val notesJson: String,
)

/**
 * HTTPS transport for mobile wallet review and submission. A transfer bundle is
 * returned only when the configured control-cluster quorum reports the exact
 * checkpoint already finalized by [MobileLightNode] and agrees on every input
 * note. The Rust wallet core remains the final identity, freshness, value,
 * canonical-encoding, review, and signature authority.
 */
class WalletApiTransport(
    private val chainId: String,
    private val genesisHash: String,
    minimumControlClusterQuorum: UByte,
    endpoints: List<MobileNodeEndpoint>,
) {
    private val minimumControlClusterQuorum = minimumControlClusterQuorum.toInt()
    private val endpoints = endpoints.toList()

    init {
        require(HASH64.matches(chainId) && HASH64.matches(genesisHash)) { "invalid_wallet_api_identity" }
        require(this.minimumControlClusterQuorum in 2..16) { "invalid_wallet_api_quorum" }
        require(this.endpoints.size in this.minimumControlClusterQuorum..16) {
            "invalid_wallet_api_endpoints"
        }
        require(this.endpoints.map { it.baseUrl }.toSet().size == this.endpoints.size) {
            "duplicate_wallet_api_endpoint"
        }
        require(this.endpoints.map { it.endpointId }.toSet().size == this.endpoints.size) {
            "duplicate_wallet_api_id"
        }
        require(this.endpoints.map { it.controlCluster }.toSet().size >= this.minimumControlClusterQuorum) {
            "insufficient_wallet_api_control_clusters"
        }
    }

    @Throws(IOException::class)
    fun fetchTransferBundle(
        transactionSpecJson: String,
        trustedSnapshot: MobileNodeSnapshot,
    ): WalletTransferBundle {
        require(trustedSnapshot.chainId == chainId && trustedSnapshot.genesisHash == genesisHash) {
            "wallet_api_snapshot_identity_mismatch"
        }
        val noteIds = parseNoteInputs(transactionSpecJson)
        val observations = endpoints.mapNotNull { endpoint ->
            try {
                val status = request(endpoint.baseUrl + "/api/status")
                if (!matchesTrustedCheckpoint(status.body, trustedSnapshot)) return@mapNotNull null
                val notes = noteIds.map { noteId ->
                    parseLiveNote(request(endpoint.baseUrl + "/api/v1/notes/$noteId").body, noteId)
                }
                EndpointBundle(endpoint, status.body, notes)
            } catch (_: IOException) {
                null
            } catch (_: RuntimeException) {
                null
            }
        }

        val agreement = observations
            .groupBy { it.notes }
            .values
            .map { group -> group.distinctBy { it.endpoint.controlCluster } }
            .filter { it.size >= minimumControlClusterQuorum }
            .maxByOrNull { it.size }
            ?: throw IOException("wallet_api_note_quorum_unavailable")
        val notesJson = JSONArray().apply {
            agreement.first().notes.forEach { put(it.toJson()) }
        }.toString()
        return WalletTransferBundle(
            statusJson = agreement.first().statusJson,
            notesJson = notesJson,
        )
    }

    @Throws(IOException::class)
    fun submit(submissionJson: String, trustedSnapshot: MobileNodeSnapshot): String {
        if (submissionJson.isBlank() || submissionJson.toByteArray(Charsets.UTF_8).size > MAX_RESPONSE_BYTES) {
            throw IOException("wallet_api_invalid_submission")
        }
        var lastFailure: IOException? = null
        for (endpoint in endpoints) {
            try {
                val status = request(endpoint.baseUrl + "/api/status")
                if (!matchesTrustedCheckpoint(status.body, trustedSnapshot)) continue
                val response = request(
                    endpoint.baseUrl + SUBMIT_PATH,
                    method = "POST",
                    requestBody = submissionJson,
                )
                if (response.status == HttpURLConnection.HTTP_ACCEPTED) return response.body
                if (response.status in 400..499) {
                    throw IOException("wallet_api_submission_rejected_${response.status}")
                }
                lastFailure = IOException("wallet_api_submit_status_${response.status}")
            } catch (error: IOException) {
                lastFailure = error
            }
        }
        throw lastFailure ?: IOException("wallet_api_submission_unavailable")
    }

    private fun matchesTrustedCheckpoint(raw: String, snapshot: MobileNodeSnapshot): Boolean {
        val status = JSONObject(raw)
        if (status.getString("chain_id") != chainId || status.getString("genesis_hash") != genesisHash) {
            return false
        }
        if (!status.optBoolean("ready", false) || status.optString("readiness") != "ready") return false
        val finalized = status.getJSONObject("finalized")
        return parseUnsigned(finalized.get("height")) == snapshot.finalizedHeight &&
            finalized.getString("hash") == snapshot.finalizedHash
    }

    private fun parseNoteInputs(transactionSpecJson: String): List<String> {
        if (transactionSpecJson.isBlank() || transactionSpecJson.length > MAX_RESPONSE_BYTES) {
            throw IllegalArgumentException("wallet_api_invalid_transaction_spec")
        }
        val values = JSONObject(transactionSpecJson).getJSONArray("note_inputs")
        if (values.length() !in 1..256) throw IllegalArgumentException("wallet_api_invalid_note_inputs")
        val notes = buildList(values.length()) {
            for (index in 0 until values.length()) {
                val noteId = values.getString(index)
                if (!HASH64.matches(noteId)) throw IllegalArgumentException("wallet_api_invalid_note_id")
                add(noteId)
            }
        }
        if (notes.toSet().size != notes.size) throw IllegalArgumentException("wallet_api_duplicate_note_id")
        return notes
    }

    private fun parseLiveNote(raw: String, expectedNoteId: String): LiveNoteView {
        val value = JSONObject(raw)
        val noteId = value.getString("note_id")
        val assetId = value.getString("asset_id")
        val amount = value.get("amount").toString()
        val createdHeight = value.get("created_height").toString()
        val spent = value.getBoolean("spent")
        if (noteId != expectedNoteId || !HASH64.matches(noteId) || !HASH64.matches(assetId) ||
            !DECIMAL.matches(amount) || !DECIMAL.matches(createdHeight)
        ) {
            throw IOException("wallet_api_malformed_note")
        }
        return LiveNoteView(noteId, assetId, amount, createdHeight, spent)
    }

    private fun request(
        url: String,
        method: String = "GET",
        requestBody: String? = null,
    ): HttpResponse {
        val connection = URL(url).openConnection() as? HttpURLConnection
            ?: throw IOException("wallet_api_transport_unavailable")
        try {
            connection.instanceFollowRedirects = false
            connection.requestMethod = method
            connection.connectTimeout = CONNECT_TIMEOUT_MS
            connection.readTimeout = READ_TIMEOUT_MS
            connection.setRequestProperty("Accept", "application/vnd.noos.v1+json, application/json")
            connection.setRequestProperty("User-Agent", "MindChain-Mobile-Wallet/1")
            if (requestBody != null) {
                val bytes = requestBody.toByteArray(Charsets.UTF_8)
                connection.doOutput = true
                connection.setFixedLengthStreamingMode(bytes.size)
                connection.setRequestProperty("Content-Type", "application/vnd.noos.v1+json")
                connection.outputStream.use { output -> output.write(bytes) }
            }
            val status = connection.responseCode
            val contentType = connection.contentType?.substringBefore(';')?.trim()
            if (contentType != "application/json" && contentType != "application/vnd.noos.v1+json") {
                throw IOException("wallet_api_invalid_content_type")
            }
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
                ?: throw IOException("wallet_api_http_status_$status")
            val body = stream.use(::readBounded).toString(Charsets.UTF_8)
            if (method == "GET" && status != HttpURLConnection.HTTP_OK) {
                throw IOException("wallet_api_http_status_$status")
            }
            return HttpResponse(status, body)
        } finally {
            connection.disconnect()
        }
    }

    private fun readBounded(input: java.io.InputStream): ByteArray {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        var total = 0
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            total += count
            if (total > MAX_RESPONSE_BYTES) throw IOException("wallet_api_response_too_large")
            output.write(buffer, 0, count)
        }
        return output.toByteArray()
    }

    private data class HttpResponse(val status: Int, val body: String)

    private data class EndpointBundle(
        val endpoint: MobileNodeEndpoint,
        val statusJson: String,
        val notes: List<LiveNoteView>,
    )

    private data class LiveNoteView(
        val noteId: String,
        val assetId: String,
        val amount: String,
        val createdHeight: String,
        val spent: Boolean,
    ) {
        fun toJson(): JSONObject = JSONObject()
            .put("note_id", noteId)
            .put("asset_id", assetId)
            .put("amount", amount)
            .put("created_height", createdHeight)
            .put("spent", spent)
    }

    companion object {
        private const val SUBMIT_PATH = "/api/v1/transactions"
        private const val MAX_RESPONSE_BYTES = 1_048_576
        private const val CONNECT_TIMEOUT_MS = 10_000
        private const val READ_TIMEOUT_MS = 10_000
        private val HASH64 = Regex("^[0-9a-f]{64}$")
        private val DECIMAL = Regex("^(0|[1-9][0-9]{0,38})$")

        private fun parseUnsigned(value: Any): ULong = when (value) {
            is Number -> value.toLong().takeIf { it >= 0 }?.toULong()
            is String -> value.toULongOrNull()
            else -> null
        } ?: throw IllegalArgumentException("wallet_api_invalid_height")
    }
}
