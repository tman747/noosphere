package org.noosphere.wallet

import android.content.Context
import org.json.JSONObject
import org.noosphere.wallet.core.MobileNodeEndpoint

internal data class MindChainNetwork(
    val enabled: Boolean,
    val disabledReason: String?,
    val chainId: String,
    val genesisHash: String,
    val maximumFreshnessMs: ULong,
    val minimumControlClusterQuorum: UByte,
    val endpoints: List<MobileNodeEndpoint>,
) {
    init {
        require(HASH64.matches(chainId)) { "invalid_chain_id" }
        require(HASH64.matches(genesisHash)) { "invalid_genesis_hash" }
        require(maximumFreshnessMs in 1UL..300_000UL) { "invalid_freshness_boundary" }
        require(minimumControlClusterQuorum.toUInt() in 2U..16U) { "invalid_quorum_boundary" }
        if (enabled) {
            require(disabledReason == null) { "enabled_network_has_disabled_reason" }
            require(endpoints.size in minimumControlClusterQuorum.toInt()..16) {
                "insufficient_network_endpoints"
            }
            require(endpoints.map { it.controlCluster }.toSet().size >= minimumControlClusterQuorum.toInt()) {
                "insufficient_control_cluster_quorum"
            }
        } else {
            require(!disabledReason.isNullOrBlank()) { "disabled_network_missing_reason" }
            require(endpoints.isEmpty()) { "disabled_network_has_endpoints" }
        }
    }

    fun requireEnabled(): MindChainNetwork {
        if (!enabled) throw NetworkDisabledException(disabledReason!!)
        return this
    }

    fun chainIdBytes(): ByteArray = chainId.chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()

    companion object {
        private val HASH64 = Regex("^[0-9a-f]{64}$")

        fun load(context: Context): MindChainNetwork {
            val root = context.resources.openRawResource(R.raw.network_endpoints)
                .bufferedReader(Charsets.UTF_8)
                .use { JSONObject(it.readText()) }
            val enabled = root.getBoolean("enabled")
            val rawEndpoints = root.getJSONArray("endpoints")
            val endpoints = buildList(rawEndpoints.length()) {
                for (index in 0 until rawEndpoints.length()) {
                    val value = rawEndpoints.getJSONObject(index)
                    add(
                        MobileNodeEndpoint(
                            baseUrl = value.getString("base_url"),
                            endpointId = value.getString("endpoint_id"),
                            controlCluster = value.getString("control_cluster"),
                        ),
                    )
                }
            }
            return MindChainNetwork(
                enabled = enabled,
                disabledReason = root.optString("disabled_reason").takeIf(String::isNotBlank),
                chainId = root.getString("chain_id"),
                genesisHash = root.getString("genesis_hash"),
                maximumFreshnessMs = root.get("maximum_freshness_ms").toString().toULong(),
                minimumControlClusterQuorum = root.getInt("minimum_control_cluster_quorum").toUByte(),
                endpoints = endpoints,
            )
        }
    }
}

internal class NetworkDisabledException(val reason: String) : IllegalStateException(reason)
