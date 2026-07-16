import Foundation

struct WalletTransferMaterial: Sendable {
    let statusJSON: String
    let notesJSON: String
}

enum WalletAPIError: Error, Equatable {
    case invalidRequest
    case invalidResponse
    case responseTooLarge
    case quorumUnavailable
    case submissionRejected(Int)
    case transportUnavailable
}

private final class WalletNoRedirectDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
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

actor MindChainWalletAPIClient {
    private struct LiveNote: Hashable, Codable, Sendable {
        let noteID: String
        let assetID: String
        let amount: String
        let createdHeight: String
        let spent: Bool

        enum CodingKeys: String, CodingKey {
            case noteID = "note_id"
            case assetID = "asset_id"
            case amount
            case createdHeight = "created_height"
            case spent
        }
    }

    private struct EndpointObservation {
        let endpoint: MindChainNetworkConfiguration.Endpoint
        let statusJSON: String
        let notes: [LiveNote]
    }

    private static let maximumResponseBytes = 1_048_576
    private let configuration: MindChainNetworkConfiguration
    private let session: URLSession

    init(configuration: MindChainNetworkConfiguration) throws {
        self.configuration = try configuration.requireEnabled()
        let sessionConfiguration = URLSessionConfiguration.ephemeral
        sessionConfiguration.timeoutIntervalForRequest = 10
        sessionConfiguration.timeoutIntervalForResource = 20
        sessionConfiguration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        sessionConfiguration.urlCache = nil
        sessionConfiguration.httpCookieStorage = nil
        sessionConfiguration.httpShouldSetCookies = false
        self.session = URLSession(
            configuration: sessionConfiguration,
            delegate: WalletNoRedirectDelegate(),
            delegateQueue: nil
        )
    }

    deinit {
        session.invalidateAndCancel()
    }

    func fetchTransferMaterial(
        transactionSpecJSON: String,
        trustedSnapshot: MobileNodeSnapshot
    ) async throws -> WalletTransferMaterial {
        guard trustedSnapshot.chainId == configuration.chainID,
              trustedSnapshot.genesisHash == configuration.genesisHash else {
            throw WalletAPIError.invalidRequest
        }
        let noteIDs = try parseNoteIDs(transactionSpecJSON)
        var observations: [EndpointObservation] = []
        observations.reserveCapacity(configuration.endpoints.count)
        for endpoint in configuration.endpoints {
            do {
                let statusData = try await get(endpointURL(endpoint, path: "api/status"))
                guard try matchesTrustedCheckpoint(statusData, snapshot: trustedSnapshot),
                      let statusJSON = String(data: statusData, encoding: .utf8) else {
                    continue
                }
                var notes: [LiveNote] = []
                notes.reserveCapacity(noteIDs.count)
                for noteID in noteIDs {
                    let data = try await get(endpointURL(endpoint, path: "api/v1/notes/\(noteID)"))
                    notes.append(try parseLiveNote(data, expectedID: noteID))
                }
                observations.append(EndpointObservation(endpoint: endpoint, statusJSON: statusJSON, notes: notes))
            } catch {
                continue
            }
        }

        let quorum = Dictionary(grouping: observations, by: \.notes)
            .values
            .map { group in
                Dictionary(grouping: group, by: { $0.endpoint.controlCluster })
                    .compactMap { $0.value.first }
            }
            .filter { $0.count >= Int(configuration.minimumControlClusterQuorum) }
            .max(by: { $0.count < $1.count })
        guard let agreement = quorum, let selected = agreement.first else {
            throw WalletAPIError.quorumUnavailable
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let notesData = try encoder.encode(selected.notes)
        guard let notesJSON = String(data: notesData, encoding: .utf8) else {
            throw WalletAPIError.invalidResponse
        }
        return WalletTransferMaterial(statusJSON: selected.statusJSON, notesJSON: notesJSON)
    }

    func submit(_ submissionJSON: String, trustedSnapshot: MobileNodeSnapshot) async throws -> String {
        guard let body = submissionJSON.data(using: .utf8),
              !body.isEmpty, body.count <= Self.maximumResponseBytes else {
            throw WalletAPIError.invalidRequest
        }
        var lastError: Error = WalletAPIError.transportUnavailable
        for endpoint in configuration.endpoints {
            do {
                let status = try await get(endpointURL(endpoint, path: "api/status"))
                guard try matchesTrustedCheckpoint(status, snapshot: trustedSnapshot) else { continue }
                var request = URLRequest(url: endpointURL(endpoint, path: "api/v1/transactions"))
                request.httpMethod = "POST"
                request.httpBody = body
                request.setValue("application/vnd.noos.v1+json", forHTTPHeaderField: "Content-Type")
                request.setValue("application/vnd.noos.v1+json, application/json", forHTTPHeaderField: "Accept")
                request.setValue("MindChain-Mobile-Wallet/1", forHTTPHeaderField: "User-Agent")
                let (responseBody, response) = try await execute(request)
                if response.statusCode == 202,
                   let value = String(data: responseBody, encoding: .utf8) {
                    return value
                }
                if (400...499).contains(response.statusCode) {
                    throw WalletAPIError.submissionRejected(response.statusCode)
                }
                lastError = WalletAPIError.transportUnavailable
            } catch {
                lastError = error
            }
        }
        throw lastError
    }

    private func get(_ url: URL) async throws -> Data {
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("application/vnd.noos.v1+json, application/json", forHTTPHeaderField: "Accept")
        request.setValue("MindChain-Mobile-Wallet/1", forHTTPHeaderField: "User-Agent")
        let (data, response) = try await execute(request)
        guard response.statusCode == 200 else { throw WalletAPIError.invalidResponse }
        return data
    }

    private func execute(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        do {
            let (bytes, rawResponse) = try await session.bytes(for: request)
            guard let response = rawResponse as? HTTPURLResponse,
                  response.url?.scheme == "https",
                  response.mimeType == "application/json" ||
                    response.mimeType == "application/vnd.noos.v1+json" else {
                throw WalletAPIError.invalidResponse
            }
            if response.expectedContentLength > Int64(Self.maximumResponseBytes) {
                throw WalletAPIError.responseTooLarge
            }
            var data = Data()
            data.reserveCapacity(
                response.expectedContentLength > 0
                    ? min(Int(response.expectedContentLength), Self.maximumResponseBytes)
                    : 8_192
            )
            for try await byte in bytes {
                guard data.count < Self.maximumResponseBytes else {
                    throw WalletAPIError.responseTooLarge
                }
                data.append(byte)
            }
            guard !data.isEmpty else { throw WalletAPIError.invalidResponse }
            return (data, response)
        } catch let error as WalletAPIError {
            throw error
        } catch {
            throw WalletAPIError.transportUnavailable
        }
    }

    private func matchesTrustedCheckpoint(
        _ data: Data,
        snapshot: MobileNodeSnapshot
    ) throws -> Bool {
        guard let status = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              status["chain_id"] as? String == configuration.chainID,
              status["genesis_hash"] as? String == configuration.genesisHash,
              status["readiness"] as? String == "ready",
              status["ready"] as? Bool == true,
              let finalized = status["finalized"] as? [String: Any],
              let height = unsigned(finalized["height"]),
              let hash = finalized["hash"] as? String else {
            throw WalletAPIError.invalidResponse
        }
        return height == snapshot.finalizedHeight && hash == snapshot.finalizedHash
    }

    private func parseNoteIDs(_ raw: String) throws -> [String] {
        guard let data = raw.data(using: .utf8),
              !data.isEmpty, data.count <= Self.maximumResponseBytes,
              let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let values = root["note_inputs"] as? [String],
              (1...256).contains(values.count),
              Set(values).count == values.count,
              values.allSatisfy(Self.isHash) else {
            throw WalletAPIError.invalidRequest
        }
        return values
    }

    private func parseLiveNote(_ data: Data, expectedID: String) throws -> LiveNote {
        guard let value = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let noteID = value["note_id"] as? String, noteID == expectedID,
              let assetID = value["asset_id"] as? String,
              Self.isHash(noteID), Self.isHash(assetID),
              let amount = decimal(value["amount"]),
              let createdHeight = decimal(value["created_height"]),
              let spent = value["spent"] as? Bool else {
            throw WalletAPIError.invalidResponse
        }
        return LiveNote(
            noteID: noteID,
            assetID: assetID,
            amount: amount,
            createdHeight: createdHeight,
            spent: spent
        )
    }

    private func endpointURL(
        _ endpoint: MindChainNetworkConfiguration.Endpoint,
        path: String
    ) -> URL {
        URL(string: endpoint.baseURL)!.appendingPathComponent(path)
    }

    private func unsigned(_ value: Any?) -> UInt64? {
        if value is Bool { return nil }
        if let string = value as? String { return UInt64(string) }
        if let number = value as? NSNumber, number.int64Value >= 0 {
            return number.uint64Value
        }
        return nil
    }

    private func decimal(_ value: Any?) -> String? {
        let text: String
        if value is Bool { return nil }
        if let string = value as? String {
            text = string
        } else if let number = value as? NSNumber {
            text = number.stringValue
        } else {
            return nil
        }
        guard text.range(of: "^(0|[1-9][0-9]{0,38})$", options: .regularExpression) != nil else {
            return nil
        }
        return text
    }

    private static func isHash(_ value: String) -> Bool {
        value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
    }
}
