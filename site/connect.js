(() => {
  const nodes = {
    apiLight: document.getElementById("connect-api-light"),
    apiTitle: document.getElementById("connect-api-title"),
    apiCopy: document.getElementById("connect-api-copy"),
    surfaceGrid: document.getElementById("surface-grid"),
    platformGrid: document.getElementById("platform-grid"),
    ladder: document.getElementById("connection-ladder"),
    blockers: document.getElementById("public-blockers")
  };

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

  async function initialize() {
    checkApi();
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

  initialize();
})();
