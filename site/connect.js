(() => {
  const nodes = {
    apiLight: document.getElementById("connect-api-light"),
    apiTitle: document.getElementById("connect-api-title"),
    apiCopy: document.getElementById("connect-api-copy"),
    surfaceGrid: document.getElementById("surface-grid"),
    platformGrid: document.getElementById("platform-grid"),
    ladder: document.getElementById("connection-ladder"),
    blockers: document.getElementById("public-blockers"),
    profileTitle: document.getElementById("profile-title"),
    profileCopy: document.getElementById("profile-copy"),
    profileChainId: document.getElementById("profile-chain-id"),
    profileGenesis: document.getElementById("profile-genesis"),
    downloadProfile: document.getElementById("download-profile"),
    profileStatus: document.getElementById("profile-status")
  };
  let connectionProfile = null;

  function escapeHtml(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function readable(value) {
    return String(value || "unknown").replace(/_/g, " ");
  }

  function statusClass(status) {
    if (/working/.test(status)) return "live";
    if (/development|source_present/.test(status)) return "building";
    return "horizon";
  }

  function renderSurfaces(surfaces) {
    nodes.surfaceGrid.innerHTML = surfaces.map((surface) => `
      <article class="connection-card">
        <div class="connection-card-top">
          <span class="state-pill ${statusClass(surface.status)}">${escapeHtml(readable(surface.status))}</span>
          <span>${escapeHtml(readable(surface.kind))}</span>
        </div>
        <h3>${escapeHtml(surface.label)}</h3>
        <p>${escapeHtml(surface.trust_boundary)}</p>
        <a class="connection-link" href="${escapeHtml(surface.href)}">Open ${escapeHtml(surface.label)} <span aria-hidden="true">↗</span></a>
      </article>
    `).join("");
  }

  function renderArtifacts(artifacts) {
    if (!Array.isArray(artifacts) || !artifacts.length) return "";
    return `
      <details class="soft-disclosure">
        <summary>Available artifacts</summary>
        <ul class="artifact-list">
          ${artifacts.map((artifact) => `
            <li>
              <a href="${escapeHtml(artifact.href)}">${escapeHtml(readable(artifact.kind))}</a>
              ${artifact.sha256 ? `<code>${escapeHtml(artifact.sha256)}</code>` : ""}
            </li>
          `).join("")}
        </ul>
      </details>
    `;
  }

  function renderPlatforms(platforms) {
    nodes.platformGrid.innerHTML = platforms.map((platform) => `
      <article class="platform-card">
        <div class="connection-card-top">
          <span class="state-pill ${statusClass(platform.status)}">${escapeHtml(readable(platform.status))}</span>
        </div>
        <h3>${escapeHtml(platform.label)}</h3>
        <p>${escapeHtml(platform.next)}</p>
        ${platform.entry
          ? `<a class="connection-link" href="${escapeHtml(platform.entry)}">Open current surface <span aria-hidden="true">↗</span></a>`
          : Array.isArray(platform.artifacts) && platform.artifacts.length
            ? '<span class="platform-not-ready">Development artifacts available below</span>'
            : '<span class="platform-not-ready">No installable artifact yet</span>'}
        ${renderArtifacts(platform.artifacts)}
      </article>
    `).join("");
  }

  function renderLists(manifest) {
    nodes.ladder.innerHTML = manifest.connection_ladder.map((step) => `<li>${escapeHtml(step)}</li>`).join("");
    nodes.blockers.innerHTML = manifest.blocked_before_public_everywhere.map((blocker) => `<li>${escapeHtml(readable(blocker))}</li>`).join("");
  }

  async function checkApi() {
    try {
      const response = await fetch("/api/health", { headers: { "Accept": "application/json" } });
      const payload = await response.json();
      nodes.apiLight.className = "connection-light online";
      nodes.apiTitle.textContent = "Local API online";
      nodes.apiCopy.textContent = `${payload.mindlinks} indexed MindLink${payload.mindlinks === 1 ? "" : "s"}. Private drafts remain browser-only.`;
    } catch (error) {
      nodes.apiLight.className = "connection-light offline";
      nodes.apiTitle.textContent = "Local API offline";
      nodes.apiCopy.textContent = "Static surfaces still open, but persistence and live index connections are unavailable.";
    }
  }

  async function loadManifest() {
    try {
      const response = await fetch("/api/connect", { headers: { "Accept": "application/json" } });
      if (!response.ok) throw new Error("API manifest unavailable");
      return await response.json();
    } catch (error) {
      const fallback = await fetch("connect-manifest.json", { headers: { "Accept": "application/json" } });
      if (!fallback.ok) throw new Error("Connection manifest unavailable");
      return fallback.json();
    }
  }

  async function loadConnectionProfile() {
    try {
      const response = await fetch("/api/connect/profile", { headers: { "Accept": "application/json" } });
      const profile = await response.json();
      if (
        !response.ok ||
        profile.schema !== "mindchain/universal-connection-profile/v0" ||
        !profile.network ||
        !profile.network.chain_id ||
        !profile.network.genesis_hash ||
        !profile.policy ||
        profile.policy.operator_rpc_included !== false ||
        profile.policy.secrets_included !== false
      ) {
        throw new Error("invalid connection profile");
      }
      connectionProfile = profile;
      nodes.profileTitle.textContent = `${profile.label} identity ready.`;
      nodes.profileCopy.textContent = "Local-device profile only. It carries chain identity and sanitized service addresses, but no wallet seed, control key, operator RPC, or other secret.";
      nodes.profileChainId.textContent = profile.network.chain_id;
      nodes.profileGenesis.textContent = profile.network.genesis_hash;
      nodes.downloadProfile.disabled = false;
      nodes.profileStatus.textContent = "Sanitized local profile ready. No secrets or operator RPC included.";
    } catch (error) {
      connectionProfile = null;
      nodes.profileTitle.textContent = "Local connection profile unavailable.";
      nodes.profileCopy.textContent = "Start the connection server before configuring compatible local clients.";
      nodes.downloadProfile.disabled = true;
      nodes.profileStatus.textContent = "Connection profile unavailable.";
    }
  }

  function downloadConnectionProfile() {
    if (!connectionProfile) return;
    nodes.profileStatus.textContent = "Local connection profile downloaded. It only works on this device until public service addresses exist.";
    const blob = new Blob([JSON.stringify(connectionProfile, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${connectionProfile.id}.mindchain-connection.json`;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }

  async function initialize() {
    checkApi();
    loadConnectionProfile();
    try {
      const manifest = await loadManifest();
      renderSurfaces(manifest.surfaces || []);
      renderPlatforms(manifest.platforms || []);
      renderLists(manifest);
    } catch (error) {
      nodes.surfaceGrid.innerHTML = '<article class="connection-card"><p class="panel-label">Unavailable</p><h3>Connection manifest could not be loaded.</h3><p>Open the local server or inspect connect-manifest.json directly.</p></article>';
      nodes.platformGrid.innerHTML = "";
    }
  }

  nodes.downloadProfile.addEventListener("click", downloadConnectionProfile);

  initialize();
})();
