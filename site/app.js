(() => {
  const STORAGE_KEY = "mindchain.worldWideMind.contributions.v1";
  const DRAFT_KEY = "mindchain.worldWideMind.rawDraft.v1";

  const seedIdeas = [
    {
      id: "portable-ai-memory",
      title: "Portable AI memory",
      text: "People should be able to leave with their context.",
      keywords: ["ai", "memory", "portable", "context", "own", "belong", "export", "agent"],
      fallback: "both ask how people keep control of intelligence that serves them"
    },
    {
      id: "machine-claim-receipts",
      title: "Machine claim receipts",
      text: "Every answer should preserve evidence and corrections.",
      keywords: ["proof", "claim", "answer", "source", "evidence", "wrong", "correct", "truth", "ai"],
      fallback: "both care about making machine claims inspectable"
    },
    {
      id: "community-controlled-archives",
      title: "Community-controlled archives",
      text: "Knowledge needs authority, consent, and local context.",
      keywords: ["community", "local", "language", "culture", "archive", "history", "plant", "name", "preserve"],
      fallback: "both concern knowledge that should keep its source and authority"
    },
    {
      id: "open-mind-test",
      title: "Open Mind Test",
      text: "An open intelligence network must publish where it still fails.",
      keywords: ["open", "test", "owner", "control", "governance", "public", "failure", "score"],
      fallback: "both test whether the network can stay open and challengeable"
    },
    {
      id: "independent-model-link",
      title: "Independent model collaboration",
      text: "Two controlled systems should be able to work together without one owning the result.",
      keywords: ["model", "agent", "tool", "collaborate", "connect", "capability", "request", "result"],
      fallback: "both describe intelligence connecting without a central owner"
    }
  ];

  const nodes = {
    form: document.getElementById("contribution-form"),
    input: document.getElementById("contribution-input"),
    source: document.getElementById("source-input"),
    error: document.getElementById("contribution-error"),
    alert: document.getElementById("system-alert"),
    originalPreview: document.getElementById("original-preview"),
    suggestedType: document.getElementById("suggested-type"),
    suggestedTitle: document.getElementById("suggested-title"),
    suggestedSummary: document.getElementById("suggested-summary"),
    editWords: document.getElementById("edit-words"),
    useExact: document.getElementById("use-exact"),
    confirmMeaning: document.getElementById("confirm-meaning"),
    backToConfirm: document.getElementById("back-to-confirm"),
    publish: document.getElementById("publish-contribution"),
    resultStatus: document.getElementById("result-status"),
    resultCopy: document.getElementById("result-copy"),
    recoveryLink: document.getElementById("recovery-link"),
    copyRecovery: document.getElementById("copy-recovery"),
    editCurrent: document.getElementById("edit-current"),
    unpublishCurrent: document.getElementById("unpublish-current"),
    exportCurrent: document.getElementById("export-current"),
    reportCurrent: document.getElementById("report-current"),
    moderationStatus: document.getElementById("moderation-status"),
    mindlinkJson: document.getElementById("mindlink-json"),
    userNode: document.getElementById("user-node"),
    relationPanel: document.getElementById("relation-panel"),
    displayName: document.getElementById("display-name"),
    trainingPermission: document.getElementById("training-permission"),
    commercialPermission: document.getElementById("commercial-permission"),
    culturalAuthority: document.getElementById("cultural-authority")
  };

  const state = {
    originalText: "",
    sourceUrl: "",
    suggested: null,
    current: null,
    usingExactWords: false
  };

  function readContributions() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      return raw ? JSON.parse(raw) : [];
    } catch (error) {
      showAlert("Saved contributions could not be read. You can still export the current contribution.");
      return [];
    }
  }

  function writeContributions(items) {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(items.slice(-100)));
      return true;
    } catch (error) {
      showAlert("Local saving is unavailable. Export this contribution before closing the page.");
      return false;
    }
  }

  function upsertContribution(contribution) {
    const items = readContributions();
    const index = items.findIndex((item) => item.id === contribution.id);
    if (index >= 0) {
      items[index] = contribution;
    } else {
      items.push(contribution);
    }
    writeContributions(items);
  }

  function saveRawDraft(text, sourceUrl) {
    try {
      localStorage.setItem(DRAFT_KEY, JSON.stringify({
        text,
        sourceUrl,
        saved_at: new Date().toISOString()
      }));
    } catch (error) {
      showAlert("The raw draft could not be saved locally. Continue, then export the result.");
    }
  }

  function showAlert(message) {
    nodes.alert.textContent = message;
    nodes.alert.hidden = false;
  }

  function clearAlert() {
    nodes.alert.textContent = "";
    nodes.alert.hidden = true;
  }

  const stepTitles = {
    1: "One field to start",
    2: "Confirm the meaning",
    3: "Choose visibility",
    4: "Control your contribution"
  };

  function showStep(stepNumber) {
    document.getElementById("flow-title").textContent = stepTitles[stepNumber] || "Contribution flow";
    document.querySelectorAll(".flow-step").forEach((step) => {
      const active = step.dataset.step === String(stepNumber);
      step.hidden = !active;
      step.classList.toggle("active", active);
    });
    document.querySelectorAll("[data-step-indicator]").forEach((indicator) => {
      indicator.classList.toggle("active", indicator.dataset.stepIndicator === String(stepNumber));
    });
  }

  function wordsFrom(text) {
    return text
      .toLowerCase()
      .replace(/[^a-z0-9\s-]/g, " ")
      .split(/\s+/)
      .filter(Boolean);
  }

  function createTitle(text) {
    const clean = text.replace(/\s+/g, " ").trim();
    const words = clean.split(" ").slice(0, 9).join(" ");
    if (!words) return "Untitled contribution";
    return words.length < clean.length ? `${words}` : words;
  }

  function inferType(text) {
    const lower = text.toLowerCase();
    if (lower.includes("?") || lower.includes("i want to know") || lower.includes("why ")) return "question";
    if (lower.includes("wrong") || lower.includes("correct") || lower.includes("fix") || lower.includes("misstate")) return "correction";
    if (lower.includes("translate") || lower.includes("language") || lower.includes("local name")) return "translation";
    if (lower.includes("remember") || lower.includes("preserve") || lower.includes("history") || lower.includes("archive")) return "memory";
    if (lower.includes("source") || lower.includes("evidence") || lower.includes("proof")) return "evidence";
    return "claim";
  }

  function summarize(text, type) {
    const clean = text.replace(/\s+/g, " ").trim();
    if (clean.length <= 150) return clean;
    const firstSentence = clean.split(/[.!?]/).find((part) => part.trim().length > 32);
    if (firstSentence) return firstSentence.trim();
    return `A ${type} contribution preserving the user's exact original words.`;
  }

  function structureContribution(text, sourceUrl) {
    if (window.__WWM_FORCE_DEGRADED === true) {
      throw new Error("Forced degraded mode");
    }
    const type = inferType(text);
    return {
      type,
      title: createTitle(text),
      summary: summarize(text, type),
      source_urls: sourceUrl ? [sourceUrl] : [],
      structured_by: "local-rule-preview"
    };
  }

  function exactStructure(text, sourceUrl) {
    return {
      type: "contribution",
      title: createTitle(text),
      summary: text,
      source_urls: sourceUrl ? [sourceUrl] : [],
      structured_by: "exact-user-words"
    };
  }

  function validateUrl(value) {
    if (!value) return true;
    try {
      const parsed = new URL(value);
      return parsed.protocol === "http:" || parsed.protocol === "https:";
    } catch (error) {
      return false;
    }
  }

  function renderPreview() {
    nodes.originalPreview.textContent = state.originalText;
    nodes.suggestedType.textContent = state.suggested.type;
    nodes.suggestedTitle.textContent = state.suggested.title;
    nodes.suggestedSummary.textContent = state.suggested.summary;
  }

  function getVisibility() {
    const checked = document.querySelector('input[name="visibility"]:checked');
    return checked ? checked.value : "only_me";
  }

  function updateVisibilityCards() {
    document.querySelectorAll(".visibility-card").forEach((card) => {
      const input = card.querySelector('input[type="radio"]');
      card.classList.toggle("selected", input.checked);
    });
    const visibility = getVisibility();
    const label = visibility === "public" ? "Publish contribution" : "Save contribution";
    nodes.publish.querySelector("span").textContent = label;
  }

  function generateId(prefix) {
    const bytes = new Uint8Array(8);
    if (crypto && crypto.getRandomValues) {
      crypto.getRandomValues(bytes);
    } else {
      for (let index = 0; index < bytes.length; index += 1) bytes[index] = Math.floor(Math.random() * 256);
    }
    const suffix = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
    return `${prefix}_${suffix}`;
  }

  async function hashText(text) {
    if (crypto && crypto.subtle && window.TextEncoder) {
      const encoded = new TextEncoder().encode(text);
      const digest = await crypto.subtle.digest("SHA-256", encoded);
      return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
    }
    let hash = 2166136261;
    for (let index = 0; index < text.length; index += 1) {
      hash ^= text.charCodeAt(index);
      hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
    }
    return `fnv1a-${(hash >>> 0).toString(16)}`;
  }

  function buildRelations(text) {
    const contributionWords = new Set(wordsFrom(text));
    const scored = seedIdeas.map((idea) => {
      const matches = idea.keywords.filter((keyword) => contributionWords.has(keyword));
      return {
        id: idea.id,
        title: idea.title,
        text: idea.text,
        reason: matches.length
          ? `Connected because both mention ${matches.slice(0, 3).join(", ")}.`
          : `Connected because ${idea.fallback}.`,
        score: matches.length,
        feedback: "unreviewed"
      };
    });
    return scored
      .sort((left, right) => right.score - left.score || left.title.localeCompare(right.title))
      .slice(0, 3);
  }

  async function buildContribution() {
    const visibility = getVisibility();
    const now = new Date().toISOString();
    const original = state.originalText.trim();
    const sourceUrls = state.suggested.source_urls || [];
    const contribution = {
      id: state.current && state.current.id ? state.current.id : generateId("mindlink"),
      recovery_token: state.current && state.current.recovery_token ? state.current.recovery_token : generateId("recover"),
      created_at: state.current && state.current.created_at ? state.current.created_at : now,
      updated_at: now,
      original_text: original,
      suggested: state.suggested,
      visibility,
      attribution: {
        mode: nodes.displayName.value.trim() ? "named" : "anonymous",
        display_name: nodes.displayName.value.trim() || "Anonymous contributor"
      },
      rights: {
        ai_training: nodes.trainingPermission.value,
        commercial_use: nodes.commercialPermission.value,
        cultural_authority: nodes.culturalAuthority.value.trim() || null,
        license: "conservative-default"
      },
      source_urls: sourceUrls,
      status: visibility === "public" ? "public" : visibility === "link" ? "unlisted" : "private_draft",
      moderation_status: state.current && state.current.moderation_status ? state.current.moderation_status : "not_reported",
      challenge_status: "unchallenged",
      relations: visibility === "public" ? buildRelations(original) : [],
      content_hash: await hashText(JSON.stringify({ original, suggested: state.suggested, source_urls: sourceUrls })),
      versions: [
        {
          at: now,
          original_text: original,
          suggested: state.suggested,
          change: state.usingExactWords ? "user_chose_exact_words" : "user_confirmed_structure"
        }
      ]
    };
    return contribution;
  }

  function toMindLink(contribution) {
    return {
      mindlink_version: "0.1",
      id: `${location.href.split("#")[0]}#${contribution.id}`,
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
        sources: contribution.source_urls,
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
        related: contribution.relations.map((relation) => ({
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
        status: contribution.challenge_status
      },
      moderation: {
        status: contribution.moderation_status
      },
      state: contribution.status,
      created_at: contribution.created_at,
      updated_at: contribution.updated_at,
      content_hash: contribution.content_hash
    };
  }

  function renderResult(contribution) {
    const isPublic = contribution.visibility === "public";
    const isLink = contribution.visibility === "link";
    nodes.resultStatus.textContent = isPublic
      ? "Public contribution added to the map."
      : isLink
        ? "Link-only contribution saved."
        : "Private draft saved.";
    nodes.resultCopy.textContent = isPublic
      ? "Your contribution is highlighted below with related ideas and control actions."
      : "Your contribution is saved locally and exportable as a MindLink. You can publish it later.";
    nodes.recoveryLink.value = `${location.href.split("#")[0]}#recover=${encodeURIComponent(contribution.recovery_token)}`;
    nodes.moderationStatus.textContent = `Moderation status: ${readableStatus(contribution.moderation_status)}.`;
    nodes.mindlinkJson.textContent = JSON.stringify(toMindLink(contribution), null, 2);
    renderMap(contribution);
  }

  function readableStatus(value) {
    return String(value).replace(/_/g, " ");
  }

  function renderMap(contribution) {
    if (!contribution || contribution.visibility !== "public") {
      nodes.userNode.classList.remove("is-highlighted");
      nodes.userNode.innerHTML = '<span class="node-label">Your contribution</span><strong>No public contribution yet</strong><p>Choose “Public on the map” to place one here.</p>';
      nodes.relationPanel.innerHTML = '<p class="panel-label">Connected because</p><p>No public contribution has been placed yet.</p>';
      return;
    }

    nodes.userNode.classList.add("is-highlighted");
    nodes.userNode.innerHTML = `<span class="node-label">Your contribution</span><strong>${escapeHtml(contribution.suggested.title)}</strong><p>${escapeHtml(contribution.suggested.summary)}</p>`;
    const relationItems = contribution.relations.map((relation, index) => `
      <li>
        <strong>${escapeHtml(relation.title)}</strong>
        <span>${escapeHtml(relation.reason)}</span>
        <div class="relation-actions">
          <button type="button" data-relation-action="not_related" data-relation-index="${index}">Not related</button>
          <button type="button" data-relation-action="move_this" data-relation-index="${index}">Move this</button>
          <button type="button" data-relation-action="add_evidence" data-relation-index="${index}">Add evidence</button>
        </div>
        <small>Feedback: ${escapeHtml(readableStatus(relation.feedback))}</small>
      </li>
    `).join("");
    nodes.relationPanel.innerHTML = `
      <p class="panel-label">Connected because</p>
      <ul class="relation-list">${relationItems}</ul>
    `;
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function downloadContribution(contribution) {
    const mindlink = toMindLink(contribution);
    const blob = new Blob([JSON.stringify(mindlink, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${contribution.id}.mindlink.json`;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }

  function copyText(input) {
    const value = input.value || input.textContent || "";
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(value);
    }
    input.focus();
    if (input.select) input.select();
    document.execCommand("copy");
    return Promise.resolve();
  }

  function updateCurrent(contribution) {
    state.current = contribution;
    upsertContribution(contribution);
    renderResult(contribution);
  }

  function loadContributionFromHash() {
    const hash = window.location.hash.replace(/^#/, "");
    if (!hash) return null;
    const items = readContributions();
    if (hash.startsWith("recover=")) {
      const token = decodeURIComponent(hash.slice("recover=".length));
      return items.find((item) => item.recovery_token === token) || null;
    }
    return items.find((item) => item.id === hash) || null;
  }

  function restoreLatestPublicContribution() {
    const recovered = loadContributionFromHash();
    if (recovered) {
      state.current = recovered;
      state.originalText = recovered.original_text;
      state.suggested = recovered.suggested;
      nodes.input.value = recovered.original_text;
      nodes.source.value = recovered.source_urls[0] || "";
      renderResult(recovered);
      showStep(4);
      document.getElementById("contribute").scrollIntoView({ block: "start" });
      return;
    }
    const items = readContributions();
    const latestPublic = [...items].reverse().find((item) => item.visibility === "public");
    if (latestPublic) renderMap(latestPublic);
  }

  nodes.form.addEventListener("submit", (event) => {
    event.preventDefault();
    clearAlert();
    const text = nodes.input.value.trim();
    const sourceUrl = nodes.source.value.trim();
    nodes.error.hidden = true;
    nodes.error.textContent = "";

    if (!text) {
      nodes.error.textContent = "Write one thing before continuing.";
      nodes.error.hidden = false;
      nodes.input.focus();
      return;
    }
    if (!validateUrl(sourceUrl)) {
      nodes.error.textContent = "Use a full source link beginning with http or https, or leave the source blank.";
      nodes.error.hidden = false;
      nodes.source.focus();
      return;
    }

    saveRawDraft(text, sourceUrl);
    state.originalText = text;
    state.sourceUrl = sourceUrl;
    state.usingExactWords = false;
    try {
      state.suggested = structureContribution(text, sourceUrl);
    } catch (error) {
      state.suggested = exactStructure(text, sourceUrl);
      state.usingExactWords = true;
      showAlert("The structuring service was unavailable, so the raw contribution was saved and your exact words are being used.");
    }
    renderPreview();
    showStep(2);
  });

  nodes.editWords.addEventListener("click", () => showStep(1));

  nodes.useExact.addEventListener("click", () => {
    state.suggested = exactStructure(state.originalText, state.sourceUrl);
    state.usingExactWords = true;
    renderPreview();
    showAlert("Using your exact words. The export will still preserve a portable MindLink wrapper.");
  });

  nodes.confirmMeaning.addEventListener("click", () => {
    clearAlert();
    showStep(3);
  });

  nodes.backToConfirm.addEventListener("click", () => showStep(2));

  document.querySelectorAll('input[name="visibility"]').forEach((input) => {
    input.addEventListener("change", updateVisibilityCards);
  });
  updateVisibilityCards();

  nodes.publish.addEventListener("click", async () => {
    clearAlert();
    try {
      const contribution = await buildContribution();
      updateCurrent(contribution);
      showStep(4);
      if (contribution.visibility === "public") {
        document.getElementById("map").scrollIntoView({ block: "start" });
      }
    } catch (error) {
      showAlert("We could not complete every enrichment step, but the raw contribution remains saved as a draft.");
      const fallback = {
        id: generateId("mindlink"),
        recovery_token: generateId("recover"),
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        original_text: state.originalText,
        suggested: exactStructure(state.originalText, state.sourceUrl),
        visibility: "only_me",
        attribution: { mode: "anonymous", display_name: "Anonymous contributor" },
        rights: { ai_training: "deny", commercial_use: "deny", cultural_authority: null, license: "conservative-default" },
        source_urls: state.sourceUrl ? [state.sourceUrl] : [],
        status: "private_draft",
        moderation_status: "not_reported",
        challenge_status: "unchallenged",
        relations: [],
        content_hash: await hashText(state.originalText),
        versions: []
      };
      updateCurrent(fallback);
      showStep(4);
    }
  });

  nodes.copyRecovery.addEventListener("click", async () => {
    await copyText(nodes.recoveryLink);
    showAlert("Recovery link copied. Keep it private if the contribution is private.");
  });

  nodes.editCurrent.addEventListener("click", () => {
    if (!state.current) return;
    nodes.input.value = state.current.original_text;
    nodes.source.value = state.current.source_urls[0] || "";
    showStep(1);
  });

  nodes.unpublishCurrent.addEventListener("click", () => {
    if (!state.current) return;
    const updated = {
      ...state.current,
      visibility: "only_me",
      status: "private_draft",
      updated_at: new Date().toISOString(),
      relations: []
    };
    updateCurrent(updated);
    showAlert("Contribution unpublished. It is now a private draft in this browser.");
  });

  nodes.exportCurrent.addEventListener("click", () => {
    if (!state.current) return;
    downloadContribution(state.current);
  });

  nodes.reportCurrent.addEventListener("click", () => {
    if (!state.current) return;
    const updated = {
      ...state.current,
      moderation_status: "reported_pending_review",
      updated_at: new Date().toISOString()
    };
    updateCurrent(updated);
    showAlert("Report status recorded locally. A production deployment would route this to moderation review.");
  });

  nodes.relationPanel.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-relation-action]");
    if (!button || !state.current) return;
    const index = Number(button.dataset.relationIndex);
    const action = button.dataset.relationAction;
    const relations = state.current.relations.map((relation, relationIndex) => {
      if (relationIndex !== index) return relation;
      if (action === "not_related") return { ...relation, feedback: "user_marked_not_related" };
      if (action === "move_this") return { ...relation, feedback: "user_requested_map_review" };
      return { ...relation, feedback: "user_wants_to_add_evidence" };
    });
    const updated = { ...state.current, relations, updated_at: new Date().toISOString() };
    updateCurrent(updated);
    if (action === "add_evidence") {
      showAlert("Evidence can be added by editing the contribution and adding a source link. The request was recorded.");
    }
  });

  restoreLatestPublicContribution();
})();
