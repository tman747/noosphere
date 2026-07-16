import SwiftUI

private enum Palette {
    static let canvas = Color(red: 0.969, green: 0.949, blue: 0.898)
    static let raised = Color(red: 0.984, green: 0.973, blue: 0.937)
    static let rule = Color(red: 0.804, green: 0.773, blue: 0.702)
    static let ink = Color(red: 0.110, green: 0.094, blue: 0.067)
    static let muted = Color(red: 0.420, green: 0.396, blue: 0.341)
    static let signal = Color(red: 0.722, green: 0.204, blue: 0.059)
    static let wash = Color(red: 0.933, green: 0.902, blue: 0.831)
    static let danger = Color(red: 0.722, green: 0.204, blue: 0.059)
}

struct WalletScreen: View {
    @ObservedObject var model: WalletViewModel
    @State private var confirmingDelete = false

    var body: some View {
        ZStack {
            Palette.canvas.ignoresSafeArea()
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    brandHeader
                        .padding(.top, 18)
                    Text("A wallet that verifies\nbefore it trusts.")
                        .font(.system(size: 40, weight: .light, design: .default))
                        .tracking(-1)
                        .foregroundStyle(Palette.ink)
                        .accessibilityAddTraits(.isHeader)
                        .padding(.top, 34)
                    Text("Device-bound keys. Multi-region indexer quorum. Exact transfer review.")
                        .font(.system(size: 16))
                        .foregroundStyle(Palette.muted)
                        .lineSpacing(5)
                        .padding(.top, 12)
                        .padding(.bottom, 24)

                    message
                    if let busy = model.busyLabel {
                        StatusStrip(label: "IN PROGRESS", value: busy, accent: Palette.signal)
                            .padding(.bottom, 12)
                    }
                    if !model.networkEnabled {
                        StatusStrip(
                            label: "NETWORK LOCKED",
                            value: readable(model.networkReason ?? "network_not_configured"),
                            accent: Palette.danger
                        )
                        .padding(.bottom, 12)
                    }

                    section(index: "01", title: "Finalized mobile node", description: "A durable light node accepts a checkpoint only when distinct control clusters agree and ancestry remains monotonic.") {
                        nodeDetails
                        PrimaryButton(
                            title: model.nodeSnapshot == nil ? "Synchronize node" : "Verify checkpoint",
                            enabled: model.networkEnabled && model.busyLabel == nil,
                            action: model.synchronizeNode
                        )
                    }

                    section(index: "02", title: "Device-bound wallet", description: "The seed is sealed by Secure Enclave. It never enters app storage, logs, backups, or the network.") {
                        StyledField("Wallet ID", text: $model.walletID)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        HStack(spacing: 12) {
                            StyledField("Account", text: $model.account)
                                .keyboardType(.numberPad)
                            StyledField("Index", text: $model.index)
                                .keyboardType(.numberPad)
                        }
                        if model.walletSealed {
                            KeyValue(label: "Protection", value: "SECURE ENCLAVE", accent: Palette.signal)
                            PrimaryButton(
                                title: "Authenticate and derive authority",
                                enabled: model.busyLabel == nil,
                                action: model.deriveAuthority
                            )
                            if confirmingDelete {
                                StatusStrip(
                                    label: "DESTRUCTIVE ACTION",
                                    value: "Delete the encrypted seed envelope and its Secure Enclave key?",
                                    accent: Palette.danger
                                )
                                HStack {
                                    Button("Cancel") { confirmingDelete = false }
                                        .foregroundStyle(Palette.muted)
                                    Button("Delete permanently") {
                                        confirmingDelete = false
                                        model.deleteWallet()
                                    }
                                    .foregroundStyle(Palette.danger)
                                }
                                .font(.system(size: 13, weight: .semibold, design: .monospaced))
                                .padding(.top, 8)
                            } else {
                                Button("Delete device-bound wallet") { confirmingDelete = true }
                                    .font(.system(size: 14, weight: .medium))
                                    .foregroundStyle(Palette.danger)
                                    .padding(.top, 8)
                            }
                        } else {
                            SecureField("Seed hex", text: $model.seedHex)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                                .font(.system(.body, design: .monospaced))
                                .padding(14)
                                .overlay(RoundedRectangle(cornerRadius: 4).stroke(Palette.rule))
                                .foregroundStyle(Palette.ink)
                            Toggle(isOn: $model.requireBiometry) {
                                VStack(alignment: .leading, spacing: 3) {
                                    Text("REQUIRE BIOMETRY")
                                        .font(.system(size: 11, weight: .semibold, design: .monospaced))
                                        .tracking(1.1)
                                        .foregroundStyle(Palette.ink)
                                    Text("When off, the enrolled device passcode may unlock the Secure Enclave envelope.")
                                        .font(.system(size: 13))
                                        .foregroundStyle(Palette.muted)
                                }
                            }
                            .tint(Palette.ink)
                            .padding(.vertical, 8)
                            PrimaryButton(
                                title: "Seal seed on this device",
                                enabled: model.busyLabel == nil && !model.seedHex.isEmpty,
                                action: model.importSeed
                            )
                        }
                        if let authority = model.authority {
                            KeyValue(label: "Public authority", value: authority.publicId)
                            if let key = authority.verifyingKey {
                                KeyValue(label: "Verifying key", value: key)
                            }
                            KeyValue(label: "Derivation path", value: authority.path.joined(separator: " / "))
                        }
                    }

                    section(index: "03", title: "Review, sign, submit", description: "Paste the complete canonical transfer spec. The app fetches every input note from a control-cluster quorum, validates it in Rust, and locks signing to the review hash shown below.") {
                        ZStack(alignment: .topLeading) {
                            if model.transactionSpec.isEmpty {
                                Text("Transfer spec JSON")
                                    .font(.system(size: 14))
                                    .foregroundStyle(Palette.muted)
                                    .padding(.horizontal, 16)
                                    .padding(.vertical, 18)
                                    .allowsHitTesting(false)
                            }
                            TextEditor(text: $model.transactionSpec)
                                .font(.system(size: 12, design: .monospaced))
                                .scrollContentBackground(.hidden)
                                .foregroundStyle(Palette.ink)
                                .frame(minHeight: 220)
                                .padding(8)
                                .background(Color.clear)
                        }
                        .overlay(RoundedRectangle(cornerRadius: 4).stroke(Palette.rule))
                        PrimaryButton(
                            title: "Build verified review",
                            enabled: model.networkEnabled && model.busyLabel == nil && !model.transactionSpec.isEmpty,
                            action: model.reviewTransfer
                        )
                        if let review = model.transferReview {
                            TransferReviewView(review: review)
                            PrimaryButton(
                                title: "Authenticate, sign and submit",
                                enabled: model.networkEnabled && model.walletSealed && model.busyLabel == nil,
                                action: model.signAndSubmit
                            )
                        }
                        if let result = model.submissionResult {
                            StatusStrip(
                                label: result.state,
                                value: "Transaction \(shortHash(result.txid))",
                                accent: Palette.signal
                            )
                        }
                    }

                    Rectangle().fill(Palette.rule).frame(height: 1)
                    Text("CHAIN \(shortHash(model.chainID))  ·  GENESIS \(shortHash(model.genesisHash))")
                        .font(.system(size: 10, weight: .medium, design: .monospaced))
                        .tracking(1)
                        .foregroundStyle(Palette.muted)
                        .padding(.vertical, 24)
                }
                .padding(.horizontal, 20)
            }
            .scrollDismissesKeyboard(.interactively)
        }
        .preferredColorScheme(.light)
    }

    private var brandHeader: some View {
        HStack(spacing: 12) {
            MindMark()
                .frame(width: 34, height: 34)
            VStack(alignment: .leading, spacing: 2) {
                Text("MINDCHAIN").foregroundStyle(Palette.ink)
                Text("VERIFIED MOBILE WALLET").foregroundStyle(Palette.muted)
            }
            .font(.system(size: 10, weight: .semibold, design: .monospaced))
            .tracking(1.2)
            Spacer()
            RoundedRectangle(cornerRadius: 1)
                .fill(model.networkEnabled ? Palette.signal : Palette.muted)
                .frame(width: 8, height: 8)
        }
    }

    @ViewBuilder
    private var message: some View {
        if let code = model.errorCode {
            MessageStrip(text: readable(code), error: true, dismiss: model.dismissMessage)
                .padding(.bottom, 12)
        } else if let notice = model.notice {
            MessageStrip(text: notice, error: false, dismiss: model.dismissMessage)
                .padding(.bottom, 12)
        }
    }

    @ViewBuilder
    private var nodeDetails: some View {
        if let snapshot = model.nodeSnapshot {
            KeyValue(label: "Finalized height", value: String(snapshot.finalizedHeight), accent: Palette.signal)
            KeyValue(label: "Finalized hash", value: snapshot.finalizedHash)
            KeyValue(label: "Quorum", value: "\(model.quorumClusters ?? 0) control clusters / \(model.quorumEndpoints ?? 0) endpoints")
            KeyValue(label: "State sequence", value: String(snapshot.sequence))
            KeyValue(label: "Retained checkpoints", value: String(snapshot.retainedCheckpoints))
        } else {
            StatusStrip(
                label: "NO TRUSTED CHECKPOINT",
                value: "Synchronize against the configured indexer quorum.",
                accent: Palette.muted
            )
        }
    }

    private func section<Content: View>(
        index: String,
        title: String,
        description: String,
        @ViewBuilder content: () -> Content
    ) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Rectangle().fill(Palette.rule).frame(height: 1)
            Text("\(index) / SECURITY BOUNDARY")
                .font(.system(size: 10, weight: .semibold, design: .monospaced))
                .tracking(1.2)
                .foregroundStyle(Palette.signal)
                .padding(.top, 26)
            Text(title)
                .font(.system(size: 24, weight: .medium))
                .foregroundStyle(Palette.ink)
                .accessibilityAddTraits(.isHeader)
                .padding(.top, 8)
            Text(description)
                .font(.system(size: 14))
                .lineSpacing(4)
                .foregroundStyle(Palette.muted)
                .padding(.top, 8)
                .padding(.bottom, 18)
            content()
                .padding(.bottom, 26)
        }
    }
}

private struct MindMark: View {
    var body: some View {
        Canvas { context, size in
            var path = Path()
            path.move(to: CGPoint(x: size.width * 0.08, y: size.height * 0.82))
            path.addLine(to: CGPoint(x: size.width * 0.34, y: size.height * 0.16))
            path.addLine(to: CGPoint(x: size.width * 0.52, y: size.height * 0.62))
            path.addLine(to: CGPoint(x: size.width * 0.72, y: size.height * 0.14))
            path.addLine(to: CGPoint(x: size.width * 0.92, y: size.height * 0.82))
            context.stroke(path, with: .color(Palette.signal), lineWidth: 2.5)
            context.fill(
                Path(ellipseIn: CGRect(x: size.width * 0.46, y: size.height * 0.56, width: 4, height: 4)),
                with: .color(Palette.signal)
            )
        }
        .accessibilityHidden(true)
    }
}

private struct StyledField: View {
    let title: String
    @Binding var text: String

    init(_ title: String, text: Binding<String>) {
        self.title = title
        self._text = text
    }

    var body: some View {
        TextField(title, text: $text)
            .font(.system(.body, design: .monospaced))
            .padding(14)
            .overlay(RoundedRectangle(cornerRadius: 4).stroke(Palette.rule))
            .foregroundStyle(Palette.ink)
            .padding(.bottom, 10)
    }
}

private struct PrimaryButton: View {
    let title: String
    let enabled: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(title.uppercased())
                .font(.system(size: 11, weight: .bold, design: .monospaced))
                .tracking(1.1)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
        }
        .buttonStyle(.plain)
        .foregroundStyle(enabled ? Palette.canvas : Palette.muted)
        .background(enabled ? Palette.ink : Palette.rule)
        .clipShape(RoundedRectangle(cornerRadius: 4))
        .disabled(!enabled)
        .padding(.top, 10)
    }
}

private struct KeyValue: View {
    let label: String
    let value: String
    var accent: Color = Palette.ink

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label.uppercased())
                .font(.system(size: 10, weight: .semibold, design: .monospaced))
                .tracking(1)
                .foregroundStyle(Palette.muted)
            Text(value)
                .font(.system(size: 14))
                .foregroundStyle(accent)
                .textSelection(.enabled)
        }
        .padding(.vertical, 6)
    }
}

private struct StatusStrip: View {
    let label: String
    let value: String
    let accent: Color

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            RoundedRectangle(cornerRadius: 1).fill(accent).frame(width: 7, height: 7).padding(.top, 4)
            VStack(alignment: .leading, spacing: 4) {
                Text(label)
                    .font(.system(size: 10, weight: .bold, design: .monospaced))
                    .tracking(1)
                    .foregroundStyle(accent)
                Text(value).font(.system(size: 13)).foregroundStyle(Palette.ink)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14)
        .background(Palette.raised)
        .clipShape(RoundedRectangle(cornerRadius: 4))
    }
}

private struct MessageStrip: View {
    let text: String
    let error: Bool
    let dismiss: () -> Void

    var body: some View {
        Button(action: dismiss) {
            HStack {
                Text(text).font(.system(size: 14)).multilineTextAlignment(.leading)
                Spacer()
                Text("DISMISS")
                    .font(.system(size: 9, weight: .bold, design: .monospaced))
                    .foregroundStyle(Palette.muted)
            }
            .foregroundStyle(error ? Palette.danger : Palette.ink)
            .padding(14)
            .background(error ? Color(red: 0.949, green: 0.871, blue: 0.835) : Palette.wash)
            .clipShape(RoundedRectangle(cornerRadius: 4))
        }
        .buttonStyle(.plain)
        .accessibilityLabel("\(text). Dismiss")
    }
}

private struct TransferReviewView: View {
    let review: TransferReview

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("EXACT REVIEW")
                .font(.system(size: 10, weight: .bold, design: .monospaced))
                .tracking(1)
                .foregroundStyle(Palette.signal)
            KeyValue(label: "Review ID", value: review.reviewId)
            KeyValue(label: "Transaction ID", value: review.txid)
            KeyValue(label: "Fee payer", value: review.feePayer)
            KeyValue(label: "Expiry height", value: String(review.expiryHeight))
            KeyValue(label: "Observed finalized", value: String(review.observedFinalizedHeight))
            ForEach(Array(review.inputTotals.enumerated()), id: \.offset) { _, amount in
                KeyValue(label: "Input \(shortHash(amount.assetId))", value: amount.amount)
            }
            ForEach(Array(review.outputs.enumerated()), id: \.offset) { index, output in
                KeyValue(
                    label: "Output \(index + 1)",
                    value: "\(output.amount) · \(shortHash(output.assetId))"
                )
                KeyValue(label: "Output lock", value: shortHash(output.lockRoot))
            }
        }
        .padding(16)
        .background(Palette.wash)
        .clipShape(RoundedRectangle(cornerRadius: 4))
        .padding(.top, 14)
    }
}

private func shortHash(_ value: String) -> String {
    guard value.count > 20 else { return value }
    return "\(value.prefix(8))…\(value.suffix(8))"
}

private func readable(_ value: String) -> String {
    value.lowercased().replacingOccurrences(of: "_", with: " ").capitalized
}
