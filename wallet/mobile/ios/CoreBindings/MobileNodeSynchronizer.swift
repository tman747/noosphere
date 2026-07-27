import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public struct MindChainMobileNodeEndpoint: Sendable, Equatable {
    public let baseURL: URL
    public let endpointID: String
    public let controlCluster: String

    public init(baseURL: URL, endpointID: String, controlCluster: String) throws {
        guard baseURL.scheme == "https",
              baseURL.host != nil,
              baseURL.user == nil,
              baseURL.password == nil,
              baseURL.query == nil,
              baseURL.fragment == nil,
              baseURL.path.isEmpty || baseURL.path == "/",
              baseURL.port == nil || baseURL.port == 443,
              Self.hashPattern(endpointID),
              Self.hashPattern(controlCluster) else {
            throw MindChainMobileNodeError.invalidEndpoint
        }
        var components = URLComponents()
        components.scheme = "https"
        components.host = baseURL.host?.lowercased()
        guard let canonical = components.url else {
            throw MindChainMobileNodeError.invalidEndpoint
        }
        self.baseURL = canonical
        self.endpointID = endpointID
        self.controlCluster = controlCluster
    }

    private static func hashPattern(_ value: String) -> Bool {
        value.count == 64 && value.utf8.allSatisfy { byte in
            (48...57).contains(byte) || (97...102).contains(byte)
        }
    }
}

public enum MindChainMobileNodeError: Error, Equatable {
    case invalidEndpoint
    case invalidEndpointSet
    case transportUnavailable
    case invalidResponse
    case responseTooLarge
    case stateUnavailable
}

private final class NoRedirectSessionDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

/**
 * A bounded mobile node over configured public indexer control clusters. HTTPS
 * transports bytes; the shared Rust core owns chain identity, freshness,
 * control-cluster quorum, ancestry, monotonicity, and durable-state checks.
 */
public actor MindChainMobileNodeSynchronizer {
    private static let maximumResponseBytes = 1_048_576
    private static let maximumEndpoints = 16

    private let endpoints: [MindChainMobileNodeEndpoint]
    private let node: MobileLightNode
    private let stateURL: URL
    private let session: URLSession

    public init(
        chainID: String,
        genesisHash: String,
        maximumFreshnessMilliseconds: UInt64,
        minimumControlClusterQuorum: UInt8,
        endpoints: [MindChainMobileNodeEndpoint],
        stateDirectory: URL
    ) throws {
        guard endpoints.count >= Int(minimumControlClusterQuorum),
              endpoints.count <= Self.maximumEndpoints,
              Set(endpoints.map(\.baseURL)).count == endpoints.count,
              Set(endpoints.map(\.endpointID)).count == endpoints.count else {
            throw MindChainMobileNodeError.invalidEndpointSet
        }
        try FileManager.default.createDirectory(
            at: stateDirectory,
            withIntermediateDirectories: true
        )
        var directoryValues = URLResourceValues()
        directoryValues.isExcludedFromBackup = true
        var protectedDirectory = stateDirectory
        try protectedDirectory.setResourceValues(directoryValues)
        let stateURL = stateDirectory.appendingPathComponent(
            "mindchain-light-node-v1.json",
            isDirectory: false
        )
        let persisted: String?
        if FileManager.default.fileExists(atPath: stateURL.path) {
            let data = try Data(contentsOf: stateURL, options: [.mappedIfSafe])
            guard !data.isEmpty, data.count <= Self.maximumResponseBytes,
                  let value = String(data: data, encoding: .utf8) else {
                throw MindChainMobileNodeError.stateUnavailable
            }
            persisted = value
        } else {
            persisted = nil
        }
        self.endpoints = endpoints
        self.stateURL = stateURL
        self.node = try MobileLightNode(
            chainId: chainID,
            genesisHash: genesisHash,
            apiVersion: "v1",
            maximumFreshnessMs: maximumFreshnessMilliseconds,
            minimumControlClusterQuorum: minimumControlClusterQuorum,
            persistedStateJson: persisted
        )
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 10
        configuration.timeoutIntervalForResource = 20
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.httpMaximumConnectionsPerHost = 2
        self.session = URLSession(
            configuration: configuration,
            delegate: NoRedirectSessionDelegate(),
            delegateQueue: nil
        )
    }

    deinit {
        session.invalidateAndCancel()
    }

    public func snapshot() throws -> MobileNodeSnapshot {
        try node.snapshot()
    }

    public func synchronize() async throws -> MobileNodeSyncOutcome {
        let current = try node.snapshot()
        var observations: [EndpointStatusObservation] = []
        observations.reserveCapacity(endpoints.count)
        for endpoint in endpoints {
            do {
                let status = try await getJSON(
                    endpoint.baseURL.appendingPathComponent("api/status")
                )
                let ancestorHash: String?
                if current.finalizedHeight == 0 {
                    ancestorHash = nil
                } else {
                    let block = try await getJSON(
                        endpoint.baseURL
                            .appendingPathComponent("api/v1/blocks")
                            .appendingPathComponent(String(current.finalizedHeight))
                    )
                    guard let object = try JSONSerialization.jsonObject(with: block) as? [String: Any],
                          let hash = object["hash"] as? String else {
                        throw MindChainMobileNodeError.invalidResponse
                    }
                    ancestorHash = hash
                }
                guard let statusJSON = String(data: status, encoding: .utf8) else {
                    throw MindChainMobileNodeError.invalidResponse
                }
                observations.append(
                    EndpointStatusObservation(
                        endpointId: endpoint.endpointID,
                        controlCluster: endpoint.controlCluster,
                        statusJson: statusJSON,
                        ancestorHash: ancestorHash
                    )
                )
            } catch {
                continue
            }
        }
        let outcome = try node.observeFinalized(observations: observations)
        try persist(outcome.persistedStateJson)
        return outcome
    }

    private func getJSON(_ url: URL) async throws -> Data {
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.timeoutInterval = 10
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        request.setValue(
            "application/vnd.noos.v1+json, application/json",
            forHTTPHeaderField: "Accept"
        )
        request.setValue("MindChain-Mobile-Node/1", forHTTPHeaderField: "User-Agent")
        let (data, response) = try await session.data(for: request)
        guard data.count <= Self.maximumResponseBytes else {
            throw MindChainMobileNodeError.responseTooLarge
        }
        guard let http = response as? HTTPURLResponse,
              http.statusCode == 200,
              let contentType = http.value(forHTTPHeaderField: "Content-Type")?
                .split(separator: ";", maxSplits: 1).first,
              contentType == "application/json" || contentType == "application/vnd.noos.v1+json" else {
            throw MindChainMobileNodeError.invalidResponse
        }
        return data
    }

    private func persist(_ value: String) throws {
        guard let data = value.data(using: .utf8),
              !data.isEmpty,
              data.count <= Self.maximumResponseBytes else {
            throw MindChainMobileNodeError.stateUnavailable
        }
        try data.write(to: stateURL, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var protectedState = stateURL
        try protectedState.setResourceValues(values)
    }
}
