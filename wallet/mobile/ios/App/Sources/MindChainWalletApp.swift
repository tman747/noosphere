import SwiftUI

@main
struct MindChainWalletApp: App {
    @UIApplicationDelegateAdaptor(MindChainAppDelegate.self) private var appDelegate
    @StateObject private var model = WalletViewModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            WalletScreen(model: model)
                .privacySensitive()
        }
        .onChange(of: scenePhase) { phase in
            switch phase {
            case .active:
                if model.networkEnabled && model.nodeSnapshot == nil {
                    model.synchronizeNode()
                }
            case .background:
                appDelegate.scheduleNodeRefresh()
            default:
                break
            }
        }
    }
}
