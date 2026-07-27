import Foundation

struct MindChainNetworkConfiguration: Decodable, Sendable {
    struct Endpoint: Decodable, Sendable, Hashable {
        let baseURL: String
        let endpointID: String
        let controlCluster: String

        enum CodingKeys: String, CodingKey {
            case baseURL = "base_url"
            case endpointID = "endpoint_id"
            case controlCluster = "control_cluster"
        }

        func mobileNodeEndpoint() throws -> MindChainMobileNodeEndpoint {
            guard let url = URL(string: baseURL) else { throw ConfigurationError.invalidEndpoint }
            return try MindChainMobileNodeEndpoint(
                baseURL: url,
                endpointID: endpointID,
                controlCluster: controlCluster
            )
        }
    }

    let enabled: Bool
    let disabledReason: String?
    let chainID: String
    let genesisHash: String
    let apiVersion: String
    let maximumFreshnessMilliseconds: UInt64
    let minimumControlClusterQuorum: UInt8
    let endpoints: [Endpoint]

    enum CodingKeys: String, CodingKey {
        case enabled
        case disabledReason = "disabled_reason"
        case chainID = "chain_id"
        case genesisHash = "genesis_hash"
        case apiVersion = "api_version"
        case maximumFreshnessMilliseconds = "maximum_freshness_ms"
        case minimumControlClusterQuorum = "minimum_control_cluster_quorum"
        case endpoints
    }

    enum ConfigurationError: Error, Equatable {
        case missingProfile
        case malformedProfile
        case invalidIdentity
        case invalidBoundary
        case invalidEndpoint
        case disabled(String)
    }

    static func load(bundle: Bundle = .main) throws -> Self {
        guard let url = bundle.url(forResource: "network_endpoints", withExtension: "json") else {
            throw ConfigurationError.missingProfile
        }
        let value: Self
        do {
            let data = try Data(contentsOf: url, options: [.mappedIfSafe])
            guard !data.isEmpty, data.count <= 1_048_576 else {
                throw ConfigurationError.malformedProfile
            }
            value = try JSONDecoder().decode(Self.self, from: data)
        } catch let error as ConfigurationError {
            throw error
        } catch {
            throw ConfigurationError.malformedProfile
        }
        try value.validate()
        return value
    }

    func requireEnabled() throws -> Self {
        guard enabled else {
            throw ConfigurationError.disabled(disabledReason ?? "network_not_configured")
        }
        return self
    }

    func chainIDData() throws -> Data {
        guard let data = Data(strictHex: chainID), data.count == 32 else {
            throw ConfigurationError.invalidIdentity
        }
        return data
    }

    func mobileNodeEndpoints() throws -> [MindChainMobileNodeEndpoint] {
        try endpoints.map { try $0.mobileNodeEndpoint() }
    }

    private func validate() throws {
        guard Self.isHash(chainID), Self.isHash(genesisHash), apiVersion == "v1" else {
            throw ConfigurationError.invalidIdentity
        }
        guard (1...300_000).contains(maximumFreshnessMilliseconds),
              (2...16).contains(minimumControlClusterQuorum) else {
            throw ConfigurationError.invalidBoundary
        }
        if enabled {
            guard disabledReason == nil,
                  endpoints.count >= Int(minimumControlClusterQuorum),
                  endpoints.count <= 16,
                  Set(endpoints.map(\.baseURL)).count == endpoints.count,
                  Set(endpoints.map(\.endpointID)).count == endpoints.count,
                  Set(endpoints.map(\.controlCluster)).count >= Int(minimumControlClusterQuorum) else {
                throw ConfigurationError.invalidEndpoint
            }
            _ = try mobileNodeEndpoints()
        } else {
            guard let reason = disabledReason, !reason.isEmpty, endpoints.isEmpty else {
                throw ConfigurationError.malformedProfile
            }
        }
    }

    private static func isHash(_ value: String) -> Bool {
        value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
    }
}

extension Data {
    init?(strictHex value: String) {
        guard value.count.isMultiple(of: 2), !value.isEmpty,
              value.range(of: "^[0-9a-fA-F]+$", options: .regularExpression) != nil else {
            return nil
        }
        var bytes = [UInt8]()
        bytes.reserveCapacity(value.count / 2)
        var cursor = value.startIndex
        while cursor < value.endIndex {
            let next = value.index(cursor, offsetBy: 2)
            guard let byte = UInt8(value[cursor..<next], radix: 16) else { return nil }
            bytes.append(byte)
            cursor = next
        }
        self.init(bytes)
        bytes.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) }
    }
}
