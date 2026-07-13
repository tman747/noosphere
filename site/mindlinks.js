(() => {
  const CONTRIBUTION_KEY = "mindchain.worldWideMind.contributions.v1";
  const IMPORT_KEY = "mindchain.worldWideMind.importedMindlinks.v1";

  const exampleMindLink = {
    mindlink_version: "0.1",
    id: "https://mindchain.network/examples/community-archive-correction",
    type: "correction",
    title: "Correcting a community archive summary",
    language: "en",
    content: {
      original_text: "The public story should say the archive was rebuilt by teachers and volunteers, not by the city office alone.",
      summary: "A correction preserving community credit for rebuilding an archive."
    },
    authority: {
      contributor: "anonymous",
      community: "river-market teachers circle"
    },
    provenance: {
      sources: ["https://example.org/community-archive-note"],
      derived_from: []
    },
    rights: {
      visibility: "public",
      ai_training: "conditional",
      commercial_use: "deny",
      license: "community-review-required",
      cultural_authority: "river-market teachers circle"
    },
    relations: {
      related: [
        {
          id: "community-controlled-archives",
          title: "Community-controlled archives",
          reason: "Connected because both protect local authority over public memory.",
          feedback: "unreviewed"
        }
      ],
      supports: [],
      contradicts: [],
      translates: [],
      extends: []
    },
    challenge: {
      status: "unchallenged"
    },
    moderation: {
      status: "not_reported"
    },
    state: "public",
    created_at: "2026-07-13T00:00:00.000Z",
    updated_at: "2026-07-13T00:00:00.000Z",
    content_hash: "example-community-archive-correction"
  };

  const nodes = {
    importJson: document.getElementById("import-json"),
    importButton: document.getElementById("import-button"),
    loadExample: document.getElementById("load-example"),
    importStatus: document.getElementById("import-status"),
    list: document.getElementById("mindlink-list"),
    statTotal: document.getElementById("stat-total"),
    statPublic: document.getElementById("stat-public"),
    statImported: document.getElementById("stat-imported")
  };

  let activeFilter = "all";

  function readJsonStorage(key) {
    try {
      const raw = localStorage.getItem(key);
      return raw ? JSON.parse(raw) : [];
    } catch (error) {
      return [];
    }
  }

  function writeJsonStorage(key, value) {
    localStorage.setItem(key, JSON.stringify(value));
  }

  function contributionToMindLink(contribution) {
    return {
      mindlink_version: "0.1",
      id: `${location.href.replace(/mindlinks\.html.*/, "index.html")}#${contribution.id}`,
      type: contribution.suggested.type,
      title: contribution.suggested.title,
      language: "en",
      content: {
        original_text: contribution.original_text,
        summary: contribution.suggested.summary
      },
      authority: {
        contributor: contribution.attribution.mode === "named" ? contribution.attribution.display_name : "anonymous",
        community: contribution.rights.cultural_authority
      },
      provenance: {
        sources: contribution.source_urls || [],
        derived_from: []
      },
      rights: {
        visibility: contribution.visibility,
        ai_training: contribution.rights.ai_training,
        commercial_use: contribution.rights.commercial_use,
        license: contribution.rights.license,
        cultural_authority: contribution.rights.cultural_authority
      },
      relations: {
        related: (contribution.relations || []).map((relation) => ({
          id: relation.id,
          title: relation.title,
          reason: relation.reason,
          feedback: relation.feedback
        })),
        supports: [],
        contradicts: [],
        translates: [],
        extends: []
      },
      challenge: {
        status: contribution.challenge_status || "unchallenged"
      },
      moderation: {
        status: contribution.moderation_status || "not_reported"
      },
      state: contribution.status,
      created_at: contribution.created_at,
      updated_at: contribution.updated_at,
      content_hash: contribution.content_hash
    };
  }

  function allMindLinks() {
    const contributions = readJsonStorage(CONTRIBUTION_KEY).map(contributionToMindLink);
    const imports = readJsonStorage(IMPORT_KEY);
    const merged = [exampleMindLink, ...contributions, ...imports];
    const seen = new Set();
    return merged.filter((item) => {
      if (!item || !item.id || seen.has(item.id)) return false;
      seen.add(item.id);
      return true;
    });
  }

  function validateMindLink(value) {
    const required = [
      "mindlink_version",
      "id",
      "type",
      "title",
      "language",
      "content",
      "authority",
      "provenance",
      "rights",
      "relations",
      "challenge",
      "moderation",
      "state",
      "created_at",
      "updated_at",
      "content_hash"
    ];
    const missing = required.filter((key) => !(key in value));
    if (missing.length) return { ok: false, message: `Missing required fields: ${missing.join(", ")}.` };
    if (value.mindlink_version !== "0.1") return { ok: false, message: "MindLink version must be 0.1." };
    if (!value.content || typeof value.content.original_text !== "string" || !value.content.original_text.trim()) {
      return { ok: false, message: "Content must include original_text." };
    }
    if (!value.rights || !["only_me", "link", "public"].includes(value.rights.visibility)) {
      return { ok: false, message: "Rights must include visibility: only_me, link, or public." };
    }
    if (!value.challenge || !value.moderation) return { ok: false, message: "Challenge and moderation states are required." };
    return { ok: true, message: "MindLink v0 fields are present." };
  }

  function readable(value) {
    return String(value || "unknown").replace(/_/g, " ");
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function filteredMindLinks() {
    const items = allMindLinks();
    if (activeFilter === "all") return items;
    return items.filter((item) => item.rights.visibility === activeFilter);
  }

  function renderStats(items) {
    const imported = readJsonStorage(IMPORT_KEY).length;
    nodes.statTotal.textContent = String(items.length);
    nodes.statPublic.textContent = String(items.filter((item) => item.rights.visibility === "public").length);
    nodes.statImported.textContent = String(imported);
  }

  function renderList() {
    const all = allMindLinks();
    const items = filteredMindLinks();
    renderStats(all);
    if (!items.length) {
      nodes.list.innerHTML = `
        <article class="empty-index">
          <p class="panel-label">No matches</p>
          <h3>No MindLinks match this filter.</h3>
          <p>Create a contribution on the homepage or import an exported MindLink above.</p>
        </article>
      `;
      return;
    }
    nodes.list.innerHTML = items.map((item) => {
      const relationCount = item.relations && Array.isArray(item.relations.related) ? item.relations.related.length : 0;
      return `
        <article class="mindlink-card">
          <div class="mindlink-card-top">
            <span class="state-pill ${item.rights.visibility === "public" ? "live" : item.rights.visibility === "link" ? "building" : "horizon"}">${escapeHtml(readable(item.rights.visibility))}</span>
            <span>${escapeHtml(item.type)}</span>
          </div>
          <h3>${escapeHtml(item.title)}</h3>
          <p>${escapeHtml(item.content.summary)}</p>
          <dl class="mindlink-meta">
            <div><dt>Contributor</dt><dd>${escapeHtml(item.authority.contributor)}</dd></div>
            <div><dt>AI training</dt><dd>${escapeHtml(readable(item.rights.ai_training))}</dd></div>
            <div><dt>Challenge</dt><dd>${escapeHtml(readable(item.challenge.status))}</dd></div>
            <div><dt>Relations</dt><dd>${relationCount}</dd></div>
          </dl>
          <details class="soft-disclosure">
            <summary>Inspect object</summary>
            <pre>${escapeHtml(JSON.stringify(item, null, 2))}</pre>
          </details>
        </article>
      `;
    }).join("");
  }

  nodes.loadExample.addEventListener("click", () => {
    nodes.importJson.value = JSON.stringify(exampleMindLink, null, 2);
    nodes.importStatus.textContent = "Example loaded. Import it to add a duplicate-safe local copy.";
  });

  nodes.importButton.addEventListener("click", () => {
    let parsed;
    try {
      parsed = JSON.parse(nodes.importJson.value);
    } catch (error) {
      nodes.importStatus.textContent = "Import failed: JSON could not be parsed.";
      return;
    }
    const validation = validateMindLink(parsed);
    if (!validation.ok) {
      nodes.importStatus.textContent = `Import failed: ${validation.message}`;
      return;
    }
    const imported = readJsonStorage(IMPORT_KEY);
    const next = imported.filter((item) => item.id !== parsed.id);
    next.push(parsed);
    writeJsonStorage(IMPORT_KEY, next);
    nodes.importStatus.textContent = validation.message;
    nodes.importJson.value = "";
    renderList();
  });

  document.querySelectorAll("[data-filter]").forEach((button) => {
    button.addEventListener("click", () => {
      activeFilter = button.dataset.filter;
      document.querySelectorAll("[data-filter]").forEach((item) => item.classList.toggle("active", item === button));
      renderList();
    });
  });

  renderList();
})();
