package org.noosphere.wallet

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.noosphere.wallet.core.MobileNodeSnapshot
import org.noosphere.wallet.core.TransferReview

private val Paper = Color(0xFFF7F2E5)
private val SurfaceRaised = Color(0xFFFBF8EF)
private val Rule = Color(0xFFCDC5B3)
private val Ink = Color(0xFF1C1811)
private val Muted = Color(0xFF6B6557)
private val Signal = Color(0xFFB8340F)
private val Wash = Color(0xFFEEE6D4)
private val Danger = Color(0xFFB8340F)

@Composable
internal fun MindChainTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = MaterialTheme.colorScheme.copy(
            primary = Signal,
            onPrimary = Paper,
            background = Paper,
            onBackground = Ink,
            surface = SurfaceRaised,
            onSurface = Ink,
            outline = Rule,
            error = Danger,
        ),
        typography = MaterialTheme.typography.copy(
            displaySmall = MaterialTheme.typography.displaySmall.copy(
                fontFamily = FontFamily.SansSerif,
                fontWeight = FontWeight.Light,
                fontSize = 40.sp,
                lineHeight = 44.sp,
                letterSpacing = (-1).sp,
            ),
            headlineSmall = MaterialTheme.typography.headlineSmall.copy(
                fontFamily = FontFamily.SansSerif,
                fontWeight = FontWeight.Medium,
                fontSize = 24.sp,
                lineHeight = 29.sp,
            ),
            bodyLarge = MaterialTheme.typography.bodyLarge.copy(
                fontSize = 16.sp,
                lineHeight = 24.sp,
            ),
            labelSmall = MaterialTheme.typography.labelSmall.copy(
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Medium,
                fontSize = 11.sp,
                letterSpacing = 1.3.sp,
            ),
        ),
        content = content,
    )
}

@Composable
internal fun WalletScreen(
    state: WalletAppState,
    onWalletId: (String) -> Unit,
    onAccount: (String) -> Unit,
    onIndex: (String) -> Unit,
    onSeedHex: (String) -> Unit,
    onHardwareFallback: (Boolean) -> Unit,
    onImportSeed: () -> Unit,
    onDeleteWallet: () -> Unit,
    onDeriveAuthority: () -> Unit,
    onSynchronize: () -> Unit,
    onTransactionSpec: (String) -> Unit,
    onReviewTransfer: () -> Unit,
    onSignTransfer: () -> Unit,
    onDismissMessage: () -> Unit,
) {
    val busy = state.busyLabel != null
    var confirmingDelete by rememberSaveable { mutableStateOf(false) }
    Surface(color = Paper, modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .statusBarsPadding()
                .navigationBarsPadding()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp),
        ) {
            Spacer(Modifier.height(26.dp))
            BrandHeader(state.networkEnabled)
            Spacer(Modifier.height(34.dp))
            Text(
                text = "A wallet that verifies\nbefore it trusts.",
                style = MaterialTheme.typography.displaySmall,
                color = Ink,
                modifier = Modifier.semantics { heading() },
            )
            Text(
                text = "Device-bound keys. Multi-region indexer quorum. Exact transfer review.",
                style = MaterialTheme.typography.bodyLarge,
                color = Muted,
                modifier = Modifier.padding(top = 14.dp, bottom = 26.dp),
            )

            MessageStrip(state, onDismissMessage)
            state.busyLabel?.let {
                StatusStrip(label = "IN PROGRESS", value = it, accent = Signal)
                Spacer(Modifier.height(12.dp))
            }
            if (!state.networkEnabled) {
                StatusStrip(
                    label = "NETWORK LOCKED",
                    value = readableCode(state.networkReason ?: "network_not_configured"),
                    accent = Danger,
                )
                Spacer(Modifier.height(12.dp))
            }

            Section(
                index = "01",
                title = "Finalized mobile node",
                description = "A durable light node accepts a checkpoint only when distinct control clusters agree and ancestry remains monotonic.",
            ) {
                NodeDetails(state.nodeSnapshot, state.nodeQuorumEndpoints, state.nodeQuorumClusters)
                PrimaryButton(
                    text = if (state.nodeSnapshot == null) "Synchronize node" else "Verify checkpoint",
                    enabled = state.networkEnabled && !busy,
                    onClick = onSynchronize,
                )
            }

            Section(
                index = "02",
                title = "Device-bound wallet",
                description = "The seed is sealed by StrongBox when available. It never enters app storage, logs, backups, or the network.",
            ) {
                Field(
                    value = state.walletId,
                    onValueChange = onWalletId,
                    label = "Wallet ID",
                    enabled = !busy,
                    keyboardType = KeyboardType.Ascii,
                )
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Field(
                        value = state.account,
                        onValueChange = { onAccount(it.filter(Char::isDigit)) },
                        label = "Account",
                        enabled = !busy,
                        keyboardType = KeyboardType.Number,
                        modifier = Modifier.weight(1f),
                    )
                    Field(
                        value = state.index,
                        onValueChange = { onIndex(it.filter(Char::isDigit)) },
                        label = "Index",
                        enabled = !busy,
                        keyboardType = KeyboardType.Number,
                        modifier = Modifier.weight(1f),
                    )
                }
                if (state.trustTier == null) {
                    Field(
                        value = state.seedHex,
                        onValueChange = onSeedHex,
                        label = "Seed hex",
                        enabled = !busy,
                        keyboardType = KeyboardType.Password,
                        password = true,
                    )
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(4.dp))
                            .clickable(enabled = !busy) {
                                onHardwareFallback(!state.allowHardwareFallback)
                            }
                            .padding(vertical = 8.dp),
                        verticalAlignment = Alignment.Top,
                    ) {
                        Checkbox(
                            checked = state.allowHardwareFallback,
                            onCheckedChange = onHardwareFallback,
                            enabled = !busy,
                            colors = CheckboxDefaults.colors(
                                checkedColor = Ink,
                                uncheckedColor = Muted,
                                checkmarkColor = Paper,
                            ),
                        )
                        Text(
                            text = "Allow hardware Keystore fallback. This weakens the StrongBox requirement but still rejects software-only keys.",
                            color = Muted,
                            style = MaterialTheme.typography.bodyMedium,
                            modifier = Modifier.padding(top = 10.dp, start = 4.dp),
                        )
                    }
                    PrimaryButton(
                        text = "Seal seed on this device",
                        enabled = !busy && state.seedHex.isNotBlank() && state.walletId.isNotBlank(),
                        onClick = onImportSeed,
                    )
                } else {
                    KeyValue("Protection", state.trustTier.name.replace('_', ' '), Signal)
                    PrimaryButton(
                        text = "Authenticate and derive authority",
                        enabled = !busy,
                        onClick = onDeriveAuthority,
                    )
                    if (!confirmingDelete) {
                        TextButton(
                            onClick = { confirmingDelete = true },
                            enabled = !busy,
                            colors = ButtonDefaults.textButtonColors(contentColor = Danger),
                        ) { Text("Delete device-bound wallet") }
                    } else {
                        StatusStrip(
                            label = "DESTRUCTIVE ACTION",
                            value = "Delete the encrypted seed envelope and every wallet-scoped hardware key?",
                            accent = Danger,
                        )
                        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            TextButton(
                                onClick = { confirmingDelete = false },
                                colors = ButtonDefaults.textButtonColors(contentColor = Muted),
                            ) { Text("Cancel") }
                            TextButton(
                                onClick = {
                                    confirmingDelete = false
                                    onDeleteWallet()
                                },
                                colors = ButtonDefaults.textButtonColors(contentColor = Danger),
                            ) { Text("Delete permanently") }
                        }
                    }
                }
                state.derivedAuthority?.let { authority ->
                    Spacer(Modifier.height(14.dp))
                    KeyValue("Public authority", authority.publicId)
                    authority.verifyingKey?.let { KeyValue("Verifying key", it) }
                    KeyValue("Derivation path", authority.path.joinToString(" / "))
                }
            }

            Section(
                index = "03",
                title = "Review, sign, submit",
                description = "Paste the complete canonical transfer spec. The app fetches each note from a control-cluster quorum, validates value and protocol identity in Rust, then locks signing to the review hash shown below.",
            ) {
                OutlinedTextField(
                    value = state.transactionSpec,
                    onValueChange = onTransactionSpec,
                    enabled = !busy,
                    label = { Text("Transfer spec JSON") },
                    minLines = 8,
                    maxLines = 18,
                    textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    colors = fieldColors(),
                    shape = RoundedCornerShape(4.dp),
                    modifier = Modifier.fillMaxWidth(),
                )
                PrimaryButton(
                    text = "Build verified review",
                    enabled = state.networkEnabled && !busy && state.transactionSpec.isNotBlank(),
                    onClick = onReviewTransfer,
                )
                state.transferReview?.let { review ->
                    TransferReviewDetails(review)
                    PrimaryButton(
                        text = "Authenticate, sign and submit",
                        enabled = state.networkEnabled && state.trustTier != null && !busy,
                        onClick = onSignTransfer,
                    )
                }
                state.submissionResult?.let { result ->
                    StatusStrip(
                        label = result.state,
                        value = "Transaction ${shortHash(result.txid)}",
                        accent = Signal,
                    )
                }
            }

            HorizontalDivider(color = Rule)
            Text(
                text = "CHAIN ${shortHash(state.chainId)}  ·  GENESIS ${shortHash(state.genesisHash)}",
                style = MaterialTheme.typography.labelSmall,
                color = Muted,
                modifier = Modifier.padding(vertical = 24.dp),
            )
            Spacer(Modifier.height(18.dp))
        }
    }
}

@Composable
private fun BrandHeader(networkEnabled: Boolean) {
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
        MindMark()
        Spacer(Modifier.width(12.dp))
        Column {
            Text("MINDCHAIN", style = MaterialTheme.typography.labelSmall, color = Ink)
            Text("VERIFIED MOBILE WALLET", style = MaterialTheme.typography.labelSmall, color = Muted)
        }
        Spacer(Modifier.weight(1f))
        Box(
            Modifier
                .size(8.dp)
                .background(if (networkEnabled) Signal else Muted, RoundedCornerShape(1.dp)),
        )
    }
}

@Composable
private fun MindMark() {
    Canvas(Modifier.size(34.dp)) {
        val path = Path().apply {
            moveTo(size.width * .08f, size.height * .82f)
            lineTo(size.width * .34f, size.height * .16f)
            lineTo(size.width * .52f, size.height * .62f)
            lineTo(size.width * .72f, size.height * .14f)
            lineTo(size.width * .92f, size.height * .82f)
        }
        drawPath(path, color = Signal, style = androidx.compose.ui.graphics.drawscope.Stroke(width = 2.5.dp.toPx()))
        drawCircle(Signal, radius = 2.2.dp.toPx(), center = Offset(size.width * .52f, size.height * .62f))
    }
}

@Composable
private fun Section(index: String, title: String, description: String, content: @Composable () -> Unit) {
    HorizontalDivider(color = Rule)
    Column(Modifier.padding(vertical = 26.dp)) {
        Text("$index / SECURITY BOUNDARY", style = MaterialTheme.typography.labelSmall, color = Signal)
        Text(
            title,
            style = MaterialTheme.typography.headlineSmall,
            color = Ink,
            modifier = Modifier.padding(top = 8.dp).semantics { heading() },
        )
        Text(
            description,
            style = MaterialTheme.typography.bodyMedium,
            color = Muted,
            modifier = Modifier.padding(top = 8.dp, bottom = 18.dp),
        )
        content()
    }
}

@Composable
private fun NodeDetails(snapshot: MobileNodeSnapshot?, endpoints: UInt?, clusters: UInt?) {
    if (snapshot == null) {
        StatusStrip("NO TRUSTED CHECKPOINT", "Synchronize against the configured indexer quorum.", Muted)
    } else {
        KeyValue("Finalized height", snapshot.finalizedHeight.toString(), Signal)
        KeyValue("Finalized hash", snapshot.finalizedHash)
        KeyValue("Quorum", "${clusters ?: 0U} control clusters / ${endpoints ?: 0U} endpoints")
        KeyValue("State sequence", snapshot.sequence.toString())
        KeyValue("Retained checkpoints", snapshot.retainedCheckpoints.toString())
    }
}

@Composable
private fun TransferReviewDetails(review: TransferReview) {
    Column(
        Modifier
            .fillMaxWidth()
            .background(Wash, RoundedCornerShape(4.dp))
            .padding(16.dp),
    ) {
        Text("EXACT REVIEW", style = MaterialTheme.typography.labelSmall, color = Signal)
        KeyValue("Review ID", review.reviewId)
        KeyValue("Transaction ID", review.txid)
        KeyValue("Fee payer", review.feePayer)
        KeyValue("Expiry height", review.expiryHeight.toString())
        KeyValue("Observed finalized", review.observedFinalizedHeight.toString())
        review.inputTotals.forEach { KeyValue("Input ${shortHash(it.assetId)}", it.amount) }
        review.outputs.forEachIndexed { index, output ->
            KeyValue("Output ${index + 1}", "${output.amount} · ${shortHash(output.assetId)}")
            KeyValue("Output lock", shortHash(output.lockRoot))
        }
    }
    Spacer(Modifier.height(12.dp))
    Text(
        "Signing is allowed only while a fresh quorum observation reproduces this exact review ID.",
        color = Muted,
        style = MaterialTheme.typography.bodySmall,
    )
}

@Composable
private fun Field(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    enabled: Boolean,
    keyboardType: KeyboardType,
    modifier: Modifier = Modifier.fillMaxWidth(),
    password: Boolean = false,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        enabled = enabled,
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = keyboardType),
        visualTransformation = if (password) PasswordVisualTransformation() else androidx.compose.ui.text.input.VisualTransformation.None,
        colors = fieldColors(),
        shape = RoundedCornerShape(4.dp),
        modifier = modifier.padding(bottom = 10.dp),
    )
}

@Composable
private fun fieldColors() = TextFieldDefaults.colors(
    focusedTextColor = Ink,
    unfocusedTextColor = Ink,
    disabledTextColor = Muted,
    focusedContainerColor = Color.Transparent,
    unfocusedContainerColor = Color.Transparent,
    disabledContainerColor = Color.Transparent,
    focusedIndicatorColor = Signal,
    unfocusedIndicatorColor = Rule,
    disabledIndicatorColor = Rule,
    focusedLabelColor = Signal,
    unfocusedLabelColor = Muted,
    cursorColor = Signal,
)

@Composable
private fun PrimaryButton(text: String, enabled: Boolean, onClick: () -> Unit) {
    Button(
        onClick = onClick,
        enabled = enabled,
        shape = RoundedCornerShape(4.dp),
        colors = ButtonDefaults.buttonColors(
            containerColor = Ink,
            contentColor = Paper,
            disabledContainerColor = Rule,
            disabledContentColor = Muted,
        ),
        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
    ) {
        Text(text.uppercase(), style = MaterialTheme.typography.labelSmall, modifier = Modifier.padding(vertical = 5.dp))
    }
}

@Composable
private fun KeyValue(label: String, value: String, accent: Color = Ink) {
    Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
        Text(label.uppercase(), style = MaterialTheme.typography.labelSmall, color = Muted)
        Text(value, style = MaterialTheme.typography.bodyMedium, color = accent)
    }
}

@Composable
private fun StatusStrip(label: String, value: String, accent: Color) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(SurfaceRaised, RoundedCornerShape(4.dp))
            .padding(14.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Box(Modifier.padding(top = 5.dp).size(7.dp).background(accent, RoundedCornerShape(1.dp)))
        Spacer(Modifier.width(10.dp))
        Column {
            Text(label, style = MaterialTheme.typography.labelSmall, color = accent)
            Text(value, style = MaterialTheme.typography.bodySmall, color = Ink, modifier = Modifier.padding(top = 3.dp))
        }
    }
}

@Composable
private fun MessageStrip(state: WalletAppState, onDismiss: () -> Unit) {
    val text = state.errorCode?.let(::readableCode) ?: state.notice ?: return
    val error = state.errorCode != null
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(bottom = 12.dp)
            .background(if (error) Color(0xFFF2DED5) else Wash, RoundedCornerShape(4.dp))
            .semantics { liveRegion = LiveRegionMode.Polite }
            .clickable(onClick = onDismiss)
            .padding(14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text,
            color = if (error) Danger else Ink,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.weight(1f),
        )
        Text("DISMISS", color = Muted, style = MaterialTheme.typography.labelSmall)
    }
}

private fun shortHash(value: String): String = if (value.length <= 20) value else value.take(8) + "…" + value.takeLast(8)

private fun readableCode(value: String): String = value
    .lowercase()
    .replace('_', ' ')
    .replaceFirstChar(Char::uppercase)
