import BackgroundTasks
import Foundation
import UIKit

actor MobileNodeRuntime {
    static let shared = MobileNodeRuntime()

    func synchronize(
        configuration: MindChainNetworkConfiguration
    ) async throws -> MobileNodeSyncOutcome {
        let enabled = try configuration.requireEnabled()
        let stateDirectory = try FileManager.default.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        ).appendingPathComponent("MindChainMobileNode", isDirectory: true)
        let synchronizer = try MindChainMobileNodeSynchronizer(
            chainID: enabled.chainID,
            genesisHash: enabled.genesisHash,
            maximumFreshnessMilliseconds: enabled.maximumFreshnessMilliseconds,
            minimumControlClusterQuorum: enabled.minimumControlClusterQuorum,
            endpoints: try enabled.mobileNodeEndpoints(),
            stateDirectory: stateDirectory
        )
        return try await synchronizer.synchronize()
    }
}

final class MindChainAppDelegate: NSObject, UIApplicationDelegate {
    static let nodeRefreshIdentifier = "network.mindchain.noosphere.wallet.node-refresh"

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        BGTaskScheduler.shared.register(
            forTaskWithIdentifier: Self.nodeRefreshIdentifier,
            using: nil
        ) { task in
            guard let refresh = task as? BGAppRefreshTask else {
                task.setTaskCompleted(success: false)
                return
            }
            self.handle(refresh)
        }
        scheduleNodeRefresh()
        return true
    }

    func scheduleNodeRefresh() {
        let request = BGAppRefreshTaskRequest(identifier: Self.nodeRefreshIdentifier)
        request.earliestBeginDate = Date(timeIntervalSinceNow: 15 * 60)
        do {
            try BGTaskScheduler.shared.submit(request)
        } catch {
            // iOS can refuse scheduling because of user settings or quota. The
            // foreground lifecycle still synchronizes on every activation.
        }
    }

    private func handle(_ task: BGAppRefreshTask) {
        scheduleNodeRefresh()
        let operation = Task {
            do {
                let configuration = try MindChainNetworkConfiguration.load()
                if configuration.enabled {
                    _ = try await MobileNodeRuntime.shared.synchronize(configuration: configuration)
                }
                task.setTaskCompleted(success: true)
            } catch {
                task.setTaskCompleted(success: false)
            }
        }
        task.expirationHandler = { operation.cancel() }
    }
}
