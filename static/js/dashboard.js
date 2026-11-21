
"use strict";

/* =========================================================
   EVSECURE-MIGRATE
   FRONTEND DASHBOARD CONTROLLER
========================================================= */

/* ---------------------------------------------------------
   API CONFIGURATION
--------------------------------------------------------- */

const API = {
    chargers: "/api/chargers",
    registerCharger: "/api/chargers/register",
    messages: "/api/messages",
    securityEvents: "/api/security/events",
    securityMode: "/api/security/mode",

    cryptoAnalyze: "/api/crypto/analyze",
    tampering: "/api/attack/tampering",

    migration: "/api/migration/analyze",

    collisionAnalysis: "/api/collision/analysis",
    collisionCompare: "/api/collision/compare",

    datasetEvaluation: "/api/dataset/evaluation",
    datasetRun: "/api/dataset/run"
};


/* ---------------------------------------------------------
   GLOBAL HELPERS
--------------------------------------------------------- */

const $ = (id) => document.getElementById(id);

function escapeHTML(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function formatDate(value) {
    if (!value) return "--";

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return String(value);
    }

    return date.toLocaleString();
}

function formatPercent(value) {
    const number = Number(value);

    return Number.isFinite(number)
        ? `${number.toFixed(2)}%`
        : "--";
}

function formatNumber(value) {
    const number = Number(value);

    return Number.isFinite(number)
        ? number.toLocaleString()
        : "--";
}

function showNotification(message, type = "info") {
    const container = $("notification-container");

    if (!container) {
        console.log(message);
        return;
    }

    const notification = document.createElement("div");

    notification.className = `notification ${type}`;
    notification.textContent = message;

    container.appendChild(notification);

    setTimeout(() => {
        notification.remove();
    }, 4000);
}

function showResult(elementId, content, type = "info") {
    const element = $(elementId);

    if (!element) return;

    element.classList.remove("hidden");
    element.className = `result-box ${type}`;
    element.innerHTML = content;
}

function showAnalysis(elementId, content) {
    const element = $(elementId);

    if (!element) return;

    element.classList.remove("hidden");
    element.innerHTML = content;
}
function showAttackResult(title, result) {
    const formattedResult = typeof result === "string"
        ? result
        : JSON.stringify(result, null, 2);

    showAnalysis(
        "attack-results",
        `
            <div class="analysis-result">
                <h3>${escapeHTML(title)}</h3>
                <pre class="result-json">${escapeHTML(formattedResult)}</pre>
            </div>
        `
    );
}

function showLoading(elementId, message = "Processing...") {
    const element = $(elementId);

    if (!element) return;

    element.innerHTML = `
        <div class="loading-state">
            <span class="loader"></span>
            ${escapeHTML(message)}
        </div>
    `;
}

function setButtonLoading(button, loading, text = "Processing...") {
    if (!button) return;

    if (loading) {
        button.dataset.originalText = button.innerHTML;
        button.disabled = true;
        button.textContent = text;
    } else {
        button.disabled = false;

        if (button.dataset.originalText) {
            button.innerHTML = button.dataset.originalText;
            delete button.dataset.originalText;
        }
    }
}


/* ---------------------------------------------------------
   API REQUEST HANDLER
--------------------------------------------------------- */

async function apiRequest(url, options = {}) {
    const config = {
        method: options.method || "GET",
        headers: {
            "Content-Type": "application/json",
            ...(options.headers || {})
        },
        ...options
    };

    if (config.body && typeof config.body !== "string") {
        config.body = JSON.stringify(config.body);
    }

    const response = await fetch(url, config);

    let data;

    try {
        data = await response.json();
    } catch {
        data = {};
    }

    if (!response.ok) {
        throw new Error(
            data.error ||
            data.message ||
            `Request failed with status ${response.status}`
        );
    }

    if (data.success === false) {
        throw new Error(
            data.error || data.message || "Operation failed."
        );
    }

    return data;
}


/* ---------------------------------------------------------
   MESSAGE PARSING
--------------------------------------------------------- */

function parseUserMessage(value) {
    const input = String(value || "").trim();

    if (!input) {
        throw new Error("Please enter a message.");
    }

    try {
        return JSON.parse(input);
    } catch {
        return input;
    }
}

function parseTrustedHashes(value) {
    try {
        const hashes = JSON.parse(value);

        if (!hashes || typeof hashes !== "object" || Array.isArray(hashes)) {
            throw new Error();
        }

        return hashes;

    } catch {
        throw new Error("Enter valid trusted hashes in JSON format.");
    }
}


/* ---------------------------------------------------------
   NAVIGATION
--------------------------------------------------------- */

function initializeNavigation() {
    const links = document.querySelectorAll(".nav-link");
    const sections = document.querySelectorAll(".page-section");

    links.forEach(link => {
        link.addEventListener("click", event => {
            event.preventDefault();

            const target = link.dataset.section;

            if (!target || !$ (target)) return;

            links.forEach(item => item.classList.remove("active"));
            link.classList.add("active");

            sections.forEach(section => {
                section.classList.remove("active");
            });

            $(target).classList.add("active");

            const pageName = link.textContent.trim();

            if ($("page-title")) {
                $("page-title").textContent = pageName;
            }

            if ($("breadcrumb-name")) {
                $("breadcrumb-name").textContent = pageName;
            }

            history.replaceState(null, "", `#${target}`);

            loadSectionData(target);

            if (window.lucide) {
                lucide.createIcons();
            }
        });
    });

    const initialSection = window.location.hash.replace("#", "");

    if (initialSection && $(initialSection)) {
        const initialLink = document.querySelector(
            `.nav-link[data-section="${initialSection}"]`
        );

        if (initialLink) {
            initialLink.click();
        }
    }
}

function loadSectionData(section) {
    switch (section) {
        case "dashboard":
            refreshDashboard();
            break;

        case "chargers":
            loadChargers();
            break;

        case "messages":
            loadMessages();
            break;

        case "attacks":
            loadCollisionAnalysis();
            break;

        case "dataset":
            loadDatasetEvaluation();
            break;
    }
}


/* ---------------------------------------------------------
   DASHBOARD
--------------------------------------------------------- */

async function refreshDashboard() {
    try {
        const [chargers, messages, events] = await Promise.all([
            apiRequest(API.chargers),
            apiRequest(API.messages),
            apiRequest(API.securityEvents)
        ]);

        const chargerList = chargers.chargers || chargers.data || [];
        const messageList = messages.messages || messages.data || [];
        const eventList = events.events || events.data || [];

        const stats = chargers.statistics || {};

        const transactions = stats.total_transactions ?? 0;

        $("total-chargers").textContent =
            formatNumber(stats.total_chargers ?? chargerList.length);

        $("total-messages").textContent =
            formatNumber(stats.total_messages ?? messageList.length);

        $("total-events").textContent =
            formatNumber(stats.total_security_events ?? eventList.length);

        $("total-transactions").textContent =
            formatNumber(transactions);

        renderDashboardEvents(eventList);

    } catch (error) {
        console.error("Dashboard loading error:", error);
        showNotification(error.message, "error");
    }
}

function renderDashboardEvents(events) {
    const tbody = $("dashboard-events");

    if (!tbody) return;

    if (!events.length) {
        tbody.innerHTML = `
            <tr>
                <td colspan="5" class="empty-state">
                    No security events recorded.
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = events.slice(0, 8).map(event => `
        <tr>
            <td>${escapeHTML(event.charger_id || "--")}</td>
            <td>${escapeHTML(event.event_type || "--")}</td>
            <td>${escapeHTML(event.description || "--")}</td>
            <td>
                <span class="status-badge ${severityClass(event.severity)}">
                    ${escapeHTML(event.severity || "INFO")}
                </span>
            </td>
            <td>${escapeHTML(formatDate(event.created_at))}</td>
        </tr>
    `).join("");
}

function severityClass(severity) {
    const value = String(severity || "").toUpperCase();

    if (value === "CRITICAL" || value === "HIGH") return "danger";
    if (value === "WARNING" || value === "MEDIUM") return "warning";

    return "success";
}


/* ---------------------------------------------------------
   CHARGER MANAGEMENT
--------------------------------------------------------- */

function initializeChargerForm() {
    const form = $("charger-form");

    if (!form) return;

    form.addEventListener("submit", async event => {
        event.preventDefault();

        const button = form.querySelector("button[type='submit']");

        const payload = {
            charger_id: $("charger-id").value.trim(),
            location: $("charger-location").value.trim(),
            connector_count: Number($("connector-count").value),
            protocol: $("charger-protocol").value
        };

        if (!payload.charger_id || !payload.location) {
            showNotification("Enter charger ID and location.", "error");
            return;
        }

        if (!Number.isInteger(payload.connector_count) ||
            payload.connector_count < 1) {
            showNotification("Connector count must be at least 1.", "error");
            return;
        }

        try {
            setButtonLoading(button, true, "Registering...");

            const result = await apiRequest(API.registerCharger, {
                method: "POST",
                body: payload
            });

            const credential = result.credential || result.charger_credential;

            let credentialHTML = "";

            if (credential) {
                credentialHTML = `
                    <p><strong>Charger Credential:</strong></p>
                    <code>${escapeHTML(credential)}</code>
                    <p class="small-note">
                        Save this credential securely. It may not be displayed again.
                    </p>
                `;
            }

            showResult(
                "charger-result",
                `
                    <strong>${escapeHTML(result.message || "Charger registered successfully.")}</strong>
                    ${credentialHTML}
                `,
                "success"
            );

            form.reset();

            $("connector-count").value = 1;

            await loadChargers();
            await refreshDashboard();

            showNotification("Charger registered successfully.", "success");

        } catch (error) {
            showResult(
                "charger-result",
                escapeHTML(error.message),
                "error"
            );

            showNotification(error.message, "error");

        } finally {
            setButtonLoading(button, false);
        }
    });
}

async function loadChargers() {
    const container = $("charger-list");

    if (!container) return;

    container.innerHTML = `<div class="loading-state">Loading chargers...</div>`;

    try {
        const response = await apiRequest(API.chargers);

        const chargers = response.chargers || response.data || [];

        if (!chargers.length) {
            container.innerHTML = `
                <div class="empty-state">
                    No chargers registered yet.
                </div>
            `;
            return;
        }

        container.innerHTML = chargers.map(charger => `
            <div class="charger-card">

                <div class="charger-card-header">
                    <div class="charger-icon">
                        <i data-lucide="battery-charging"></i>
                    </div>

                    <span class="status-badge ${chargerStatusClass(charger.security_mode)}">
                        ${escapeHTML(charger.security_mode || "LEGACY_MD5")}
                    </span>
                </div>

                <h3>${escapeHTML(charger.charger_id)}</h3>

                <p>${escapeHTML(charger.location || "Unknown location")}</p>

                <div class="charger-details">
                    <span>Connectors</span>
                    <strong>${escapeHTML(charger.connector_count ?? 1)}</strong>
                </div>

                <div class="charger-details">
                    <span>Protocol</span>
                    <strong>${escapeHTML(charger.protocol || "OCPP 1.6")}</strong>
                </div>

                <div class="charger-details">
                    <span>Created</span>
                    <strong>${escapeHTML(formatDate(charger.created_at))}</strong>
                </div>

                <button class="secondary-btn"
                        onclick="selectCharger('${escapeHTML(charger.charger_id)}')">
                    Configure Security
                </button>

            </div>
        `).join("");

        if (window.lucide) lucide.createIcons();

    } catch (error) {
        container.innerHTML = `
            <div class="empty-state error-text">
                ${escapeHTML(error.message)}
            </div>
        `;

        showNotification(error.message, "error");
    }
}

function chargerStatusClass(mode) {
    if (mode === "SECURE_SHA3") return "success";
    if (mode === "MIGRATION") return "warning";

    return "danger";
}

function selectCharger(chargerId) {
    $("security-charger-id").value = chargerId;

    const securityLink = document.querySelector(
        '.nav-link[data-section="security"]'
    );

    if (securityLink) securityLink.click();
}


/* ---------------------------------------------------------
   SECURITY MODE MANAGEMENT
--------------------------------------------------------- */

function initializeSecurityForm() {
    const form = $("security-form");

    if (!form) return;

    form.addEventListener("submit", async event => {
        event.preventDefault();

        const chargerId = $("security-charger-id").value.trim();
        const securityMode = $("security-mode").value;

        if (!chargerId) {
            showNotification("Enter a charger ID.", "error");
            return;
        }

        const button = form.querySelector("button[type='submit']");

        try {
            setButtonLoading(button, true, "Updating...");

            const result = await apiRequest(API.securityMode, {
                method: "POST",
                body: {
                    charger_id: chargerId,
                    security_mode: securityMode
                }
            });

            showResult(
                "security-result",
                escapeHTML(result.message || "Security mode updated successfully."),
                "success"
            );

            await loadChargers();

            showNotification("Security mode updated.", "success");

        } catch (error) {
            showResult(
                "security-result",
                escapeHTML(error.message),
                "error"
            );

            showNotification(error.message, "error");

        } finally {
            setButtonLoading(button, false);
        }
    });
}


/* ---------------------------------------------------------
   MESSAGE HISTORY
--------------------------------------------------------- */

async function loadMessages() {
    const tbody = $("message-table");

    if (!tbody) return;

    tbody.innerHTML = `
        <tr>
            <td colspan="5" class="empty-state">Loading messages...</td>
        </tr>
    `;

    try {
        const response = await apiRequest(API.messages);

        const messages = response.messages || response.data || [];

        if (!messages.length) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="5" class="empty-state">
                        No messages recorded.
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = messages.map(message => `
            <tr>
                <td>${escapeHTML(message.id ?? "--")}</td>
                <td>${escapeHTML(message.charger_id || "--")}</td>
                <td>${escapeHTML(message.message_type || "--")}</td>
                <td>
                    <span class="status-badge ${verificationClass(message.verification_status)}">
                        ${escapeHTML(message.verification_status || "PENDING")}
                    </span>
                </td>
                <td>${escapeHTML(formatDate(message.created_at))}</td>
            </tr>
        `).join("");

    } catch (error) {
        tbody.innerHTML = `
            <tr>
                <td colspan="5" class="empty-state error-text">
                    ${escapeHTML(error.message)}
                </td>
            </tr>
        `;
    }
}

function verificationClass(status) {
    const value = String(status || "").toUpperCase();

    if (value.includes("VERIFIED") || value.includes("SUCCESS")) {
        return "success";
    }

    if (value.includes("FAILED") || value.includes("REJECTED")) {
        return "danger";
    }

    return "warning";
}


/* ---------------------------------------------------------
   CRYPTOGRAPHIC HASH ANALYZER
--------------------------------------------------------- */

async function analyzeHash() {
    const input = $("hash-input").value;

    let message;

    try {
        message = parseUserMessage(input);
    } catch (error) {
        showNotification(error.message, "error");
        return;
    }

    showLoading("hash-results", "Generating cryptographic hashes...");

    try {
        const result = await apiRequest(API.cryptoAnalyze, {
            method: "POST",
            body: { message }
        });

        const responseData = result.data || result;
const algorithms = responseData.algorithms || {};
const hashes = Object.fromEntries(
    Object.entries(algorithms).map(([name, details]) => [name, details.hash])
);

        const details = Object.entries(hashes);

        if (!details.length) {
            throw new Error("No hash results returned by the server.");
        }

        showAnalysis(
            "hash-results",
            `
                <div class="hash-result-grid">
                    ${details.map(([algorithm, digest]) => `
                        <div class="hash-result-card">
                            <div class="hash-result-header">
                                <strong>${escapeHTML(algorithm.toUpperCase())}</strong>
                                <button class="copy-btn"
                                        onclick="copyText('${escapeHTML(digest)}')">
                                    Copy
                                </button>
                            </div>

                            <code>${escapeHTML(digest)}</code>
                        </div>
                    `).join("")}
                </div>
            `
        );

        showNotification("Hashes generated successfully.", "success");

    } catch (error) {
        showAnalysis(
            "hash-results",
            `<p class="error-text">${escapeHTML(error.message)}</p>`
        );

        showNotification(error.message, "error");
    }
}


/* ---------------------------------------------------------
   MD5 TO SHA3 MIGRATION
--------------------------------------------------------- */

async function analyzeMigration() {
    let message;

    try {
        message = parseUserMessage(
            $("migration-message").value
        );
    } catch (error) {
        showNotification(error.message, "error");
        return;
    }

    showLoading(
        "migration-result",
        "Running migration analysis..."
    );

    try {
        const messageText = typeof message === "string"
    ? message
    : JSON.stringify(message);

const result = await apiRequest(API.migration, {
    method: "POST",
    body: { message: messageText }
});

        const responseData = result.data || result;
const hashes = responseData.reference_hashes || responseData.hashes || responseData.migration?.hashes || {};
const comparison = responseData.comparison || responseData.analysis || {};

        showAnalysis(
            "migration-result",
            `
                <div class="result-section">
                    <h3>Migration Status</h3>
                    <span class="status-badge success">
                        ${escapeHTML(result.status || result.migration_status || "Analysis completed")}
                    </span>
                </div>

                <div class="hash-result-grid">
                    ${Object.entries(hashes).map(([algorithm, digest]) => `
                        <div class="hash-result-card">
                            <strong>${escapeHTML(algorithm.toUpperCase())}</strong>
                            <code>${escapeHTML(digest)}</code>
                        </div>
                    `).join("")}
                </div>

                <div class="result-section">
                    <h3>Algorithm Comparison</h3>
                    <pre>${escapeHTML(JSON.stringify(comparison, null, 2))}</pre>
                </div>
            `
        );

    } catch (error) {
        showAnalysis(
            "migration-result",
            `<p class="error-text">${escapeHTML(error.message)}</p>`
        );

        showNotification(error.message, "error");
    }
}


/* ---------------------------------------------------------
   SHA3 INTEGRITY VERIFICATION
--------------------------------------------------------- */

async function verifySHA3Integrity() {
    let message;
    let trustedHashes;

    try {
        message = parseUserMessage(
            $("verification-message").value ||
            $("migration-message").value
        );

        trustedHashes = parseTrustedHashes(
            $("trusted-hashes").value
        );

    } catch (error) {
        showNotification(error.message, "error");
        return;
    }

    showLoading(
        "verification-result",
        "Verifying message integrity..."
    );

    try {
        const result = await apiRequest(API.migration, {
            method: "POST",
            body: {
    message: typeof message === "string"
        ? message
        : JSON.stringify(message),
    trusted_hashes: trustedHashes,
    security_mode: "MIGRATION"
}
        });

        const responseData = result.data || result;
        const verified = Boolean(
    responseData.verified ??
    responseData.verification?.verified
);

const algorithmResults =
    responseData.algorithm_results ||
    responseData.verification?.algorithm_results ||
    {};

        showAnalysis(
            "verification-result",
            `
                <div class="verification-summary ${verified ? "success" : "danger"}">
                    <h3>${verified ? "INTEGRITY VERIFIED" : "INTEGRITY CHECK FAILED"}</h3>
                    <p>${verified
                        ? "The message matches the supplied trusted digests."
                        : "The message could not be verified against the supplied trusted digests."
                    }</p>
                </div>

                <div class="result-section">
                    <h3>Algorithm Results</h3>

                    ${Object.entries(algorithmResults).map(([algorithm, valid]) => `
                        <div class="mode-item">
                            <span class="mode-indicator ${valid ? "secure" : "legacy"}"></span>
                            <div>
                                <strong>${escapeHTML(algorithm.toUpperCase())}</strong>
                                <p>${valid ? "Verified" : "Failed"}</p>
                            </div>
                        </div>
                    `).join("")}
                </div>
            `
        );

    } catch (error) {
        showAnalysis(
            "verification-result",
            `<p class="error-text">${escapeHTML(error.message)}</p>`
        );

        showNotification(error.message, "error");
    }
}


/* ---------------------------------------------------------
   CONTROLLED TAMPERING SIMULATION
--------------------------------------------------------- */

async function simulateTampering() {
    const originalMessage =
        $("migration-message")?.value.trim() ||
        $("hash-input")?.value.trim() ||
        "EV-TEST-01 Heartbeat Available";

    const modifiedMessage = originalMessage + " TAMPERED";

    showLoading(
        "attack-results",
        "Running controlled tampering test..."
    );

    try {
        const result = await apiRequest(API.tampering, {
            method: "POST",
            body: {
                original_message: originalMessage,
                modified_message: modifiedMessage
            }
        });

        showAttackResult("Controlled Tampering", result);

    } catch (error) {
        showAttackResult("Controlled Tampering", {
            result: "Test failed",
            detail: error.message
        });
    }
}


/* ---------------------------------------------------------
   UNKNOWN CHARGER TEST
--------------------------------------------------------- */


async function simulateUnknownCharger() {
    const unknownId = "UNKNOWN-EV-999";

    showLoading("attack-results", "Testing unknown charger...");

    try {
        await apiRequest(
            `/api/chargers/${encodeURIComponent(unknownId)}/authenticate`,
            {
                method: "POST",
                body: { credential: "INVALID-TEST-CREDENTIAL" }
            }
        );

        showAttackResult("Unknown Charger Test", {
            charger_id: unknownId,
            result: "Unexpectedly accepted"
        });

    } catch (error) {
        showAttackResult("Unknown Charger Test", {
            charger_id: unknownId,
            result: "UNAUTHORIZED CHARGER — correctly rejected",
            detail: error.message
        });
    }
}


async function simulateInvalidCredential() {
    const chargerId = "EV-TEST-01";

    showLoading("attack-results", "Testing invalid credential...");

    try {
        await apiRequest(
            `/api/chargers/${encodeURIComponent(chargerId)}/authenticate`,
            {
                method: "POST",
                body: { credential: "INVALID-EVSECURE-CREDENTIAL" }
            }
        );

        showAttackResult("Invalid Credential Test", {
            charger_id: chargerId,
            result: "Unexpectedly authenticated"
        });

    } catch (error) {
        showAttackResult("Invalid Credential Test", {
            charger_id: chargerId,
            result: "AUTHENTICATION FAILED — correctly rejected",
            detail: error.message
        });
    }
}
/* ---------------------------------------------------------
   REPLAY ATTACK TEST
--------------------------------------------------------- */


async function simulateReplayAttack() {
    const chargerId = $("replay-charger-id")?.value.trim();

    if (!chargerId) {
        showNotification("Enter a charger ID.", "error");
        return;
    }

    // Ask for credentials BEFORE displaying the loading state
    const credential = prompt("Enter the registered charger credential:");

    if (!credential) {
        showNotification("Credential is required.", "error");
        return;
    }

    showLoading("attack-results", "Submitting replay test...");

    const payload = {
        charger_id: chargerId,
        credential: credential,
        message_type: "Heartbeat",
        message_id: "REPLAY-TEST-001",
        timestamp: new Date().toISOString(),
        payload: {
            status: "Available",
            test: "EVSecure replay simulation"
        }
    };

    try {
        const first = await apiRequest("/api/messages", {
            method: "POST",
            body: payload
        });

        let second;

        try {
            second = await apiRequest("/api/messages", {
                method: "POST",
                body: payload
            });
        } catch (error) {
            second = {
                rejected: true,
                detail: error.message
            };
        }

        showAttackResult("Replay Attack Test", {
            first_submission: first,
            second_submission: second,
            interpretation:
                "The same message was submitted twice. Check whether the second submission was rejected by replay protection."
        });

    } catch (error) {
        showAttackResult("Replay Attack Test", {
            result: "Test failed",
            detail: error.message
        });
    }
}



/* ---------------------------------------------------------
   COLLISION ANALYSIS
--------------------------------------------------------- */

async function loadCollisionAnalysis() {
    showLoading(
        "collision-results",
        "Loading collision analysis..."
    );

    try {
        const result = await apiRequest(API.collisionAnalysis);

        const algorithms = result.algorithms || result.analysis || {};

        const entries = Array.isArray(algorithms)
            ? algorithms.map(item => [item.algorithm, item])
            : Object.entries(algorithms);

        showAnalysis(
            "collision-results",
            `
                <div class="hash-result-grid">
                    ${entries.map(([algorithm, details]) => `
                        <div class="hash-result-card">
                            <h3>${escapeHTML(String(algorithm).toUpperCase())}</h3>

                            <p>Digest size:
                                <strong>${escapeHTML(details.digest_bits ?? "--")} bits</strong>
                            </p>

                            <p>Collision strength:
                                <strong>${escapeHTML(details.collision_strength_bits ?? "--")} bits</strong>
                            </p>

                            <p>Estimated inputs:
                                <strong>${escapeHTML(details.approx_inputs_for_50_percent_collision ?? "--")}</strong>
                            </p>

                            <span class="status-badge ${severityClass(details.status)}">
                                ${escapeHTML(details.status || "ANALYZED")}
                            </span>
                        </div>
                    `).join("")}
                </div>

                <p class="small-note">
                    These are theoretical collision estimates. They do not demonstrate
                    that a collision was generated in this application.
                </p>
            `
        );

    } catch (error) {
        showAnalysis(
            "collision-results",
            `<p class="error-text">${escapeHTML(error.message)}</p>`
        );
    }
}


/* ---------------------------------------------------------
   DATASET EVALUATION
--------------------------------------------------------- */


async function runDatasetEvaluation() {
    const button = $("run-dataset-btn");

    setButtonLoading(button, true, "Running pipeline...");

    showNotification(
        "Dataset evaluation started. This may take a little time.",
        "info"
    );

    try {
        // Run all dataset processing modules
        await apiRequest(API.datasetRun, {
            method: "POST",
            body: {}
        });

        // Fetch the latest evaluation JSON after the pipeline finishes
        const result = await apiRequest(API.datasetEvaluation);

        const evaluation = result.data?.evaluation;

        if (!evaluation || !evaluation.hash_consistency) {
            throw new Error("Latest dataset evaluation results were not returned by the server.");
        }

        renderDatasetEvaluation(evaluation);

        showNotification(
            "Dataset evaluation completed and results loaded successfully.",
            "success"
        );

    } catch (error) {
        showNotification(
            "Dataset evaluation failed: " + error.message,
            "error"
        );

        showAnalysis(
            "dataset-methodology",
            `<p class="error-text">${escapeHTML(error.message)}</p>`
        );

    } finally {
        setButtonLoading(button, false);
    }
}

async function loadDatasetEvaluation() {
    try {
        const result = await apiRequest(API.datasetEvaluation);

        const evaluation = result.data?.evaluation;

        if (!evaluation || !evaluation.hash_consistency) {
            console.warn("Dataset evaluation data is missing or incomplete.");
            return;
        }

        renderDatasetEvaluation(evaluation);

    } catch (error) {
        console.warn("Dataset evaluation not available:", error.message);
    }
}

function renderDatasetEvaluation(evaluation) {
    if (!evaluation) return;

    const consistency = evaluation.hash_consistency || {};
    const tampering = evaluation.tampering || {};
    const benchmarks = evaluation.benchmarks || [];

    const totalMessages = evaluation.total_messages ?? 0;

    $("dataset-total-messages").textContent =
        formatNumber(totalMessages);

    const consistencyValues = Object.values(consistency);

    const totalPassed = consistencyValues.reduce(
        (sum, item) => sum + Number(item.passed || 0),
        0
    );

    const totalChecked = consistencyValues.reduce(
        (sum, item) => sum + Number(item.total_messages || 0),
        0
    );

    $("dataset-consistency").textContent =
        totalChecked
            ? formatPercent((totalPassed / totalChecked) * 100)
            : "--";

    const tamperingValues = Object.values(tampering);

    const totalDetected = tamperingValues.reduce(
        (sum, item) => sum + Number(item.detected || 0),
        0
    );

    const totalTested = tamperingValues.reduce(
        (sum, item) => sum + Number(item.tested || 0),
        0
    );

    $("dataset-tampering").textContent =
        totalTested
            ? formatPercent((totalDetected / totalTested) * 100)
            : "--";

    renderConsistencyTable(consistency);
    renderTamperingTable(tampering);
    renderBenchmarkTable(benchmarks);
    renderDatasetMethodology(evaluation.methodology);
}


function renderConsistencyTable(results) {
    const tbody = $("consistency-table");

    if (!tbody) return;

    const entries = Object.entries(results || {});

    if (!entries.length) {
        tbody.innerHTML = `
            <tr><td colspan="5" class="empty-state">No results available.</td></tr>
        `;
        return;
    }

    tbody.innerHTML = entries.map(([algorithm, item]) => `
        <tr>
            <td><strong>${escapeHTML(algorithm.toUpperCase())}</strong></td>
            <td>${formatNumber(item.total_messages)}</td>
            <td class="success-text">${formatNumber(item.passed)}</td>
            <td class="error-text">${formatNumber(item.failed)}</td>
            <td>${formatPercent(item.success_rate)}</td>
        </tr>
    `).join("");
}

function renderTamperingTable(results) {
    const tbody = $("tampering-table");

    if (!tbody) return;

    const entries = Object.entries(results || {});

    if (!entries.length) {
        tbody.innerHTML = `
            <tr><td colspan="5" class="empty-state">No results available.</td></tr>
        `;
        return;
    }

    tbody.innerHTML = entries.map(([algorithm, item]) => `
        <tr>
            <td><strong>${escapeHTML(algorithm.toUpperCase())}</strong></td>
            <td>${formatNumber(item.tested)}</td>
            <td class="success-text">${formatNumber(item.detected)}</td>
            <td class="error-text">${formatNumber(item.undetected)}</td>
            <td>${formatPercent(item.detection_rate)}</td>
        </tr>
    `).join("");
}

function renderBenchmarkTable(results) {
    const tbody = $("benchmark-table");

    if (!tbody) return;

    if (!Array.isArray(results) || !results.length) {
        tbody.innerHTML = `
            <tr><td colspan="5" class="empty-state">No benchmark results available.</td></tr>
        `;
        return;
    }

    tbody.innerHTML = results.map(item => `
        <tr>
            <td><strong>${escapeHTML(String(item.algorithm || "").toUpperCase())}</strong></td>
            <td>${formatNumber(item.messages_tested)}</td>
            <td>${formatNumber(item.iterations_per_message)}</td>
            <td>${escapeHTML(item.average_time_ms ?? "--")}</td>
            <td>${formatNumber(item.operations_per_second)}</td>
        </tr>
    `).join("");
}

function renderDatasetMethodology(methodology) {
    const container = $("dataset-methodology");

    if (!container) return;

    if (!methodology) {
        container.innerHTML = `
            <p class="empty-state">No methodology details available.</p>
        `;
        return;
    }

    let html = "";

    Object.entries(methodology).forEach(([key, value]) => {
        if (Array.isArray(value)) {
            html += `
                <h4>${escapeHTML(key.replaceAll("_", " ").toUpperCase())}</h4>
                <ul>
                    ${value.map(item => `<li>${escapeHTML(item)}</li>`).join("")}
                </ul>
            `;
        } else {
            html += `
                <div class="methodology-item">
                    <strong>${escapeHTML(key.replaceAll("_", " "))}</strong>
                    <p>${escapeHTML(value)}</p>
                </div>
            `;
        }
    });

    container.innerHTML = html;
}


/* ---------------------------------------------------------
   COPY HASH
--------------------------------------------------------- */

async function copyText(value) {
    try {
        await navigator.clipboard.writeText(value);
        showNotification("Copied to clipboard.", "success");
    } catch {
        showNotification("Unable to copy text.", "error");
    }
}


/* ---------------------------------------------------------
   INITIALIZATION
--------------------------------------------------------- */

document.addEventListener("DOMContentLoaded", () => {
    initializeNavigation();
    initializeChargerForm();
    initializeSecurityForm();

    refreshDashboard();

    if (window.lucide) {
        lucide.createIcons();
    }
});


/* ---------------------------------------------------------
   GLOBAL FUNCTION EXPORTS
--------------------------------------------------------- */

window.refreshDashboard = refreshDashboard;
window.loadChargers = loadChargers;
window.loadMessages = loadMessages;

window.analyzeHash = analyzeHash;
window.analyzeMigration = analyzeMigration;
window.verifySHA3Integrity = verifySHA3Integrity;

window.simulateTampering = simulateTampering;
window.simulateUnknownCharger = simulateUnknownCharger;
window.simulateInvalidCredential = simulateInvalidCredential;
window.simulateReplayAttack = simulateReplayAttack;

window.loadCollisionAnalysis = loadCollisionAnalysis;
window.runDatasetEvaluation = runDatasetEvaluation;

window.selectCharger = selectCharger;
window.copyText = copyText;


/* =========================================================
   EVSECURE-MIGRATE - CHARGING MESSAGE SENDER
   Additive integration - preserves existing dashboard UI
========================================================= */

(function initializeChargingMessageSender() {

    function createMessageSender() {
        const messagesSection = document.getElementById("messages");

        if (!messagesSection ||
            document.getElementById("charging-message-sender")) {
            return;
        }

        const historyPanel = messagesSection.querySelector(".panel");

        if (!historyPanel) return;

        const senderPanel = document.createElement("div");

        senderPanel.id = "charging-message-sender";
        senderPanel.className = "panel";

        senderPanel.innerHTML = `
            <div class="panel-heading">
                <div>
                    <h3>Send Charging Message</h3>
                    <p>Send a simulated EV charger message to the local CSMS.</p>
                </div>
                <i data-lucide="send"></i>
            </div>

            <form id="charging-message-form">

                <div class="form-grid">

                    <div class="form-group">
                        <label for="send-charger-id">Registered Charger</label>
                        <select id="send-charger-id" required>
                            <option value="">Loading chargers...</option>
                        </select>
                    </div>

                    <div class="form-group">
                        <label for="send-message-type">Message Type</label>
                        <select id="send-message-type" required>
                            <option value="Heartbeat">Heartbeat</option>
                            <option value="StatusNotification">StatusNotification</option>
                            <option value="StartTransaction">StartTransaction</option>
                            <option value="StopTransaction">StopTransaction</option>
                            <option value="MeterValues">MeterValues</option>
                        </select>
                    </div>

                    <div class="form-group">
    <label for="send-credential">Charger Credential</label>
    <input
        type="password"
        id="send-credential"
        placeholder="Enter registered charger credential"
        autocomplete="off"
    >
</div>

                    <div class="form-group" id="send-transaction-group">
                        <label for="send-transaction-id">Transaction ID</label>
                        <input
                            type="text"
                            id="send-transaction-id"
                            placeholder="Required for transaction messages"
                        >
                    </div>

                </div>

                <div class="form-group">
                    <label for="send-message-data">Additional Message Data (JSON)</label>
                    <textarea
                        id="send-message-data"
                        rows="4"
                    >{"status":"Available"}</textarea>
                </div>

                <div class="form-actions">
                    <button type="submit" class="primary-btn" id="send-message-submit">
                        <i data-lucide="send"></i>
                        Send Message
                    </button>
                </div>

            </form>

            <div id="send-message-result"
                 class="result-box hidden"></div>
        `;

        historyPanel.parentNode.insertBefore(senderPanel, historyPanel);

        if (window.lucide) {
            lucide.createIcons();
        }

        initializeSenderControls();
    }

    async function loadSenderChargers() {
        const select = document.getElementById("send-charger-id");

        if (!select) return;

        try {
            const response = await apiRequest("/api/chargers");

            const chargers = response.chargers || response.data || [];

            if (!Array.isArray(chargers) || chargers.length === 0) {
                select.innerHTML =
                    '<option value="">No registered chargers found</option>';
                return;
            }

            select.innerHTML = `
                <option value="">Select registered charger</option>
                ${chargers.map(charger => `
                    <option value="${escapeHTML(charger.charger_id)}">
                        ${escapeHTML(charger.charger_id)}
                        (${escapeHTML(charger.security_mode || "LEGACY_MD5")})
                    </option>
                `).join("")}
            `;

            // Preselect a charger if its ID is already entered
            // in the existing security configuration form.
            const existingCharger =
                document.getElementById("security-charger-id");

            if (existingCharger && existingCharger.value) {
                select.value = existingCharger.value;
            }

        } catch (error) {
            select.innerHTML =
                '<option value="">Unable to load chargers</option>';

            console.error("Charger loading error:", error);
        }
    }

    function initializeSenderControls() {
        const form = document.getElementById("charging-message-form");
        const messageType = document.getElementById("send-message-type");
        const transactionGroup =
            document.getElementById("send-transaction-group");

        if (!form || form.dataset.initialized === "true") return;

        form.dataset.initialized = "true";

        function updateTransactionField() {
            const requiresTransaction = [
                "StartTransaction",
                "StopTransaction"
            ].includes(messageType.value);

            transactionGroup.style.display =
                requiresTransaction ? "" : "none";
        }

        messageType.addEventListener("change", updateTransactionField);
        updateTransactionField();

        form.addEventListener("submit", async function(event) {
            event.preventDefault();

            const button = document.getElementById("send-message-submit");
            const resultBox = document.getElementById("send-message-result");

            const chargerId =
                document.getElementById("send-charger-id").value;

            const credential =
                document.getElementById("send-credential").value.trim();

            const type = messageType.value;

            const transactionId =
                document.getElementById("send-transaction-id").value.trim();

            const additionalDataText =
                document.getElementById("send-message-data").value.trim();

            if (!chargerId) {
    showResult(
        "send-message-result",
        "Please select a charger.",
        "error"
    );
    return;
}

            if ([
                "StartTransaction",
                "StopTransaction"
            ].includes(type) && !transactionId) {
                showResult(
                    "send-message-result",
                    "Transaction ID is required for this message type.",
                    "error"
                );
                return;
            }

            let additionalData = {};

            try {
                additionalData = additionalDataText
                    ? JSON.parse(additionalDataText)
                    : {};

                if (
                    !additionalData ||
                    typeof additionalData !== "object" ||
                    Array.isArray(additionalData)
                ) {
                    throw new Error("Message data must be a JSON object.");
                }

            } catch (error) {
                showResult(
                    "send-message-result",
                    escapeHTML(error.message || "Invalid JSON message data."),
                    "error"
                );
                return;
            }

            const payload = {
    ...additionalData,
    charger_id: chargerId,
    credential: credential,
    message_type: type
};

            if (type === "StartTransaction" ||
                type === "StopTransaction") {
                payload.transaction_id = transactionId;
            }

            try {
                setButtonLoading(button, true, "Sending...");

                resultBox.classList.remove("hidden");

                showResult(
                    "send-message-result",
                    "Sending message to local CSMS...",
                    "info"
                );

                const response = await apiRequest("/api/messages", {
                    method: "POST",
                    body: payload
                });

                const data = response.data || response;

                const status =
                    data.integrity_status || "ACCEPTED";

                const algorithm =
                    data.integrity_algorithm || "Not specified";

                showResult(
                    "send-message-result",
                    `
                        <strong>Message accepted successfully!</strong>
                        <p>Charger: ${escapeHTML(data.charger || chargerId)}</p>
                        <p>Message Type: ${escapeHTML(data.message_type || type)}</p>
                        <p>Security Mode: ${escapeHTML(data.security_mode || "--")}</p>
                        <p>Integrity Algorithm: ${escapeHTML(algorithm)}</p>
                        <p>Verification Status:
                            <strong>${escapeHTML(status)}</strong>
                        </p>
                    `,
                    "success"
                );

                showNotification(
                    `${type} accepted by CSMS.`,
                    "success"
                );

                // Refresh message history and dashboard statistics.
                await loadMessages();
                await refreshDashboard();

                // Clear credential after successful transmission.
                document.getElementById("send-credential").value = "";

            } catch (error) {

                showResult(
                    "send-message-result",
                    `<strong>Message rejected</strong><p>${escapeHTML(error.message)}</p>`,
                    "error"
                );

                showNotification(error.message, "error");

            } finally {
                setButtonLoading(button, false);
            }
        });

        loadSenderChargers();
    }

    if (document.readyState === "loading") {
        document.addEventListener(
            "DOMContentLoaded",
            createMessageSender
        );
    } else {
        createMessageSender();
    }

    // Reload the charger list whenever the Messages section is opened.
    document.addEventListener("click", function(event) {
        const link = event.target.closest(
            '.nav-link[data-section="messages"]'
        );

        if (link) {
            setTimeout(loadSenderChargers, 100);
        }
    });

})();
