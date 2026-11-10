let isAdmin = false;

const API = "";

function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>"']/g, char => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#039;"
    })[char]);
}

function severityBadge(severity) {
    const safe = escapeHTML(severity || "Medium");
    return `<span class="severity ${safe.toLowerCase()}">${safe}</span>`;
}

function actionButtons(endpoint, id) {
    if (!isAdmin) return "";

    return `
        <button onclick="editRecord('${endpoint}', ${id})">Edit</button>
        <button class="delete-btn"
            onclick="deleteRecord('${endpoint}', ${id})">Delete</button>
    `;
}

function emptyRow(message, columns) {
    return `<tr><td colspan="${columns}">${escapeHTML(message)}</td></tr>`;
}

async function getJSON(url) {
    const response = await fetch(url, { cache: "no-store" });

    if (!response.ok) {
        throw new Error(`Request failed: ${response.status}`);
    }

    return response.json();
}

async function checkAdminStatus() {
    try {
        const data = await getJSON("/auth/status");
        isAdmin = data.authenticated;
    } catch {
        isAdmin = false;
    }

    return isAdmin;
}

async function loadDashboard() {
    try {
        const [actors, malware, iocs] = await Promise.all([
            getJSON("/threat-actors"),
            getJSON("/malware"),
            getJSON("/iocs")
        ]);

        const actorCount = document.getElementById("actorCount");
        const malwareCount = document.getElementById("malwareCount");
        const iocCount = document.getElementById("iocCount");

        if (actorCount) actorCount.textContent = actors.length;
        if (malwareCount) malwareCount.textContent = malware.length;
        if (iocCount) iocCount.textContent = iocs.length;

        loadAnalytics();
    } catch (error) {
        console.error("Dashboard error:", error);
    }
}

async function loadAnalytics() {
    const container = document.getElementById("analyticsContainer");
    if (!container) return;

    try {
        const data = await getJSON("/analytics");

        let html = `
            <div class="analytics-summary">
                <h3>Total Records: ${data.total}</h3>
            </div>
            <div class="analytics-grid">
                <div>
                    <h3>Records by Category</h3>
        `;

        const categoryColors = {
            "Threat Actors": "#8b5cf6",
            "Malware": "#22d3ee",
            "IOCs": "#f59e0b"
        };

        for (const [name, count] of Object.entries(data.categories)) {
            const percent = data.total
                ? (count / data.total) * 100
                : 0;

            html += `
                <div class="analytics-item">
                    <div class="analytics-label">
                        <span>${escapeHTML(name)}</span>
                        <strong>${count}</strong>
                    </div>
                    <div class="analytics-track">
                        <div class="analytics-bar"
                            style="width:${percent}%;background:${categoryColors[name]}">
                        </div>
                    </div>
                </div>
            `;
        }

        html += `
                </div>
                <div>
                    <h3>Records by Severity</h3>
        `;

        const severityColors = {
            Low: "#22c55e",
            Medium: "#eab308",
            High: "#f97316",
            Critical: "#ef4444"
        };

        const severityTotal = Object.values(data.severity)
            .reduce((sum, count) => sum + count, 0);

        for (const [name, count] of Object.entries(data.severity)) {
            const percent = severityTotal
                ? (count / severityTotal) * 100
                : 0;

            html += `
                <div class="analytics-item">
                    <div class="analytics-label">
                        <span>${escapeHTML(name)}</span>
                        <strong>${count}</strong>
                    </div>
                    <div class="analytics-track">
                        <div class="analytics-bar"
                            style="width:${percent}%;background:${severityColors[name] || "#8b5cf6"}">
                        </div>
                    </div>
                </div>
            `;
        }

        html += `</div></div>`;
        container.innerHTML = html;

    } catch (error) {
        console.error("Analytics error:", error);
        container.innerHTML = "<p>Unable to load analytics.</p>";
    }
}

async function loadThreatTables() {
    await checkAdminStatus();

    try {
        const [actors, malware, iocs] = await Promise.all([
            getJSON("/threat-actors"),
            getJSON("/malware"),
            getJSON("/iocs")
        ]);

        const actorTable = document.getElementById("actorsTable");
        const malwareTable = document.getElementById("malwareTable");
        const iocTable = document.getElementById("iocsTable");

        if (actorTable) {
            actorTable.innerHTML = actors.length
                ? actors.map((record, index) => `
                    <tr data-category="Threat Actor"
                        data-severity="${escapeHTML(record.severity)}"
                        data-date="${escapeHTML(record.date_recorded)}">
                        <td>${index + 1}</td>
                        <td>${escapeHTML(record.name)}</td>
                        <td>${escapeHTML(record.description)}</td>
                        <td>${escapeHTML(record.country)}</td>
                        <td>${severityBadge(record.severity)}</td>
                        <td>${escapeHTML(record.date_recorded)}</td>
                        <td>${actionButtons("threat-actors", record.id)}</td>
                    </tr>
                `).join("")
                : emptyRow("No threat actors found.", 7);
        }

        if (malwareTable) {
            malwareTable.innerHTML = malware.length
                ? malware.map((record, index) => `
                    <tr data-category="Malware"
                        data-severity="${escapeHTML(record.severity)}"
                        data-date="${escapeHTML(record.date_recorded)}">
                        <td>${index + 1}</td>
                        <td>${escapeHTML(record.name)}</td>
                        <td>${escapeHTML(record.type)}</td>
                        <td>${escapeHTML(record.description)}</td>
                        <td>${severityBadge(record.severity)}</td>
                        <td>${escapeHTML(record.date_recorded)}</td>
                        <td>${actionButtons("malware", record.id)}</td>
                    </tr>
                `).join("")
                : emptyRow("No malware records found.", 7);
        }

        if (iocTable) {
            iocTable.innerHTML = iocs.length
                ? iocs.map((record, index) => `
                    <tr data-category="IOC"
                        data-severity="${escapeHTML(record.severity)}"
                        data-date="${escapeHTML(record.date_recorded)}">
                        <td>${index + 1}</td>
                        <td>${escapeHTML(record.value)}</td>
                        <td>${escapeHTML(record.type)}</td>
                        <td>${escapeHTML(record.description)}</td>
                        <td>${severityBadge(record.severity)}</td>
                        <td>${escapeHTML(record.date_recorded)}</td>
                        <td>${actionButtons("iocs", record.id)}</td>
                    </tr>
                `).join("")
                : emptyRow("No IOC records found.", 7);
        }

        applyFilters();

    } catch (error) {
        console.error("Threat records error:", error);
    }
}

async function deleteRecord(endpoint, id) {
    if (!isAdmin) {
        alert("Only an administrator can delete records.");
        window.location.href = "/control-room";
        return;
    }

    if (!confirm("Are you sure you want to delete this record?")) return;

    try {
        const response = await fetch(`/${endpoint}/${id}`, {
            method: "DELETE",
            cache: "no-store"
        });

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.detail || "Unable to delete record");
        }

        alert("Record deleted successfully.");

        await loadThreatTables();
        await loadDashboard();

    } catch (error) {
        alert(error.message);
    }
}

async function editRecord(endpoint, id) {
    if (!isAdmin) {
        alert("Administrator access required.");
        window.location.href = "/control-room";
        return;
    }

    const fields = {
        "threat-actors": ["name", "description", "country", "severity"],
        "malware": ["name", "type", "description", "severity"],
        "iocs": ["value", "type", "description", "severity"]
    };

    const rows = document.querySelectorAll(
        endpoint === "threat-actors" ? "#actorsTable tr" :
            endpoint === "malware" ? "#malwareTable tr" : "#iocsTable tr"
    );

    const row = [...rows].find(item =>
        item.querySelector("button[onclick*='editRecord']")?.getAttribute("onclick")
            .includes(`, ${id})`)
    );

    if (!row) return;

    const cells = [...row.cells];
    const values = {};

    const fieldIndexes = {
        "threat-actors": [1, 2, 3, 4],
        "malware": [1, 2, 3, 4],
        "iocs": [1, 2, 3, 4]
    };

    const selectedFields = fields[endpoint];

    for (let i = 0; i < selectedFields.length; i++) {
        const field = selectedFields[i];
        const current = cells[fieldIndexes[endpoint][i]].innerText.trim();

        const updated = prompt(`Enter ${field}:`, current);

        if (updated === null) return;

        values[field] = updated;
    }

    try {
        const response = await fetch(`/${endpoint}/${id}`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(values)
        });

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.detail || "Unable to update record");
        }

        alert("Record updated successfully.");
        await loadThreatTables();

    } catch (error) {
        alert(error.message);
    }
}

function applyFilters() {
    const search = (
        document.getElementById("searchInput")?.value || ""
    ).toLowerCase();

    const category = document.getElementById("categoryFilter")?.value || "All";
    const severity = document.getElementById("severityFilter")?.value || "All";
    const date = document.getElementById("dateFilter")?.value || "";

    document.querySelectorAll(
        "#actorsTable tr, #malwareTable tr, #iocsTable tr"
    ).forEach(row => {
        const text = row.innerText.toLowerCase();
        const rowCategory = row.dataset.category || "";
        const rowSeverity = row.dataset.severity || "";
        const rowDate = (row.dataset.date || "").substring(0, 10);

        const matchesSearch = text.includes(search);
        const matchesCategory =
            category === "All" || category === rowCategory;
        const matchesSeverity =
            severity === "All" || severity === rowSeverity;
        const matchesDate = !date || rowDate === date;

        row.style.display =
            matchesSearch && matchesCategory &&
                matchesSeverity && matchesDate ? "" : "none";
    });
}

async function exportCSV() {
    try {
        const [actors, malware, iocs] = await Promise.all([
            getJSON("/threat-actors"),
            getJSON("/malware"),
            getJSON("/iocs")
        ]);

        const rows = [
            ["Category", "Name / Value", "Type", "Description",
                "Country", "Severity", "Date Recorded"]
        ];

        actors.forEach(record => rows.push([
            "Threat Actor", record.name, "", record.description,
            record.country, record.severity, record.date_recorded
        ]));

        malware.forEach(record => rows.push([
            "Malware", record.name, record.type, record.description,
            "", record.severity, record.date_recorded
        ]));

        iocs.forEach(record => rows.push([
            "IOC", record.value, record.type, record.description,
            "", record.severity, record.date_recorded
        ]));

        const csv = rows.map(row =>
            row.map(value =>
                `"${String(value ?? "").replace(/"/g, '""')}"`
            ).join(",")
        ).join("\n");

        const blob = new Blob([csv], {
            type: "text/csv;charset=utf-8;"
        });

        const link = document.createElement("a");
        link.href = URL.createObjectURL(blob);
        link.download = "threat_intelligence_records.csv";
        link.click();

        URL.revokeObjectURL(link.href);

    } catch (error) {
        alert("Unable to export records.");
        console.error(error);
    }
}

async function submitRecord(event, category) {
    event.preventDefault();

    const form = event.target;
    const message = document.getElementById("submissionMessage");
    const formData = new FormData(form);

    const data = Object.fromEntries(formData.entries());
    data.category = category;

    try {
        const response = await fetch("/submissions", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data)
        });

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.detail || "Submission failed");
        }

        if (message) {
            message.textContent = result.message;
            message.className = "success-message";
        }

        form.reset();

    } catch (error) {
        if (message) {
            message.textContent = error.message;
            message.className = "error-message";
        } else {
            alert(error.message);
        }
    }
}

async function initializeAdminPage() {
    const form = document.getElementById("adminForm");
    if (!form) return;

    const title = document.getElementById("adminTitle");
    const description = document.getElementById("adminDescription");
    const submit = document.getElementById("adminSubmit");
    const message = document.getElementById("adminMessage");
    const loggedIn = document.getElementById("adminLoggedIn");
    const reviewSection = document.getElementById("reviewSection");

    async function refreshStatus() {
        const status = await getJSON("/auth/status");

        if (status.authenticated) {
            if (title) title.textContent = "Administrator Panel";
            if (description) description.textContent =
                "Manage threat intelligence submissions and records.";
            if (loggedIn) loggedIn.hidden = false;
            if (reviewSection) reviewSection.hidden = false;
            form.hidden = true;

            loadSubmissionCounts();
            loadSubmissions();
            loadActivityLog();

        } else {
            form.hidden = false;

            if (loggedIn) loggedIn.hidden = true;
            if (reviewSection) reviewSection.hidden = true;

            if (status.admin_exists) {
                if (title) title.textContent = "Administrator Login";
                if (description) description.textContent =
                    "Sign in to manage the dashboard.";
                if (submit) submit.textContent = "Login";
                form.dataset.mode = "login";
            } else {
                if (title) title.textContent = "Create Administrator";
                if (description) description.textContent =
                    "Set up the first administrator account.";
                if (submit) submit.textContent = "Create Account";
                form.dataset.mode = "setup";
            }
        }
    }

    form.addEventListener("submit", async event => {
        event.preventDefault();

        const username = document.getElementById("adminUsername").value;
        const password = document.getElementById("adminPassword").value;
        const mode = form.dataset.mode;

        const endpoint = mode === "setup" ? "/auth/setup" : "/auth/login";

        try {
            const response = await fetch(endpoint, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password })
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.detail || "Authentication failed");
            }

            if (message) {
                message.textContent = result.message;
                message.className = "success-message";
            }

            form.reset();
            await refreshStatus();

        } catch (error) {
            if (message) {
                message.textContent = error.message;
                message.className = "error-message";
            }
        }
    });

    document.getElementById("logoutButton")?.addEventListener("click", async () => {
        await fetch("/auth/logout", { method: "POST" });
        window.location.href = "/dashboard";
    });

    document.getElementById("backupButton")?.addEventListener("click", async () => {
        try {
            const response = await fetch("/admin/backup");

            if (!response.ok) {
                throw new Error("Backup failed. Please log in again.");
            }

            const blob = await response.blob();
            const url = URL.createObjectURL(blob);
            const link = document.createElement("a");

            link.href = url;
            link.download = "threat_dashboard_backup.db";
            link.click();

            URL.revokeObjectURL(url);

        } catch (error) {
            alert(error.message);
        }
    });

    await refreshStatus();
}

async function loadSubmissionCounts() {
    try {
        const counts = await getJSON("/admin/submission-counts");

        for (const status of ["Pending", "Approved", "Rejected"]) {
            const element = document.getElementById(
                `${status.toLowerCase()}Count`
            );

            if (element) element.textContent = counts[status] || 0;
        }
    } catch (error) {
        console.error(error);
    }
}


async function loadSubmissions() {
    const list = document.getElementById("submissionList");
    if (!list) return;

    const status = document.getElementById("submissionStatus")?.value || "Pending";

    try {
        const submissions = await getJSON(
            `/admin/submissions?status=${encodeURIComponent(status)}`
        );

        if (!submissions.length) {
            list.innerHTML = "<p>No submissions found.</p>";
            return;
        }

        list.innerHTML = submissions.map(item => {
            const data = item.data;

            return `
                <div class="submission-card">
                    <h3>${escapeHTML(item.category)}</h3>
                    <p><strong>Record:</strong>
                        ${escapeHTML(data.name || data.value || "")}
                    </p>
                    <p><strong>Type:</strong> ${escapeHTML(data.type || "N/A")}</p>
                    <p><strong>Description:</strong>
                        ${escapeHTML(data.description || "N/A")}
                    </p>
                    <p><strong>Severity:</strong>
                        ${escapeHTML(data.severity || "Medium")}
                    </p>
                    <p><strong>Source:</strong>
                        ${escapeHTML(item.source)}
                    </p>
                    <p><strong>Submitted:</strong>
                        ${escapeHTML(item.submitted_at)}
                    </p>
                    ${status === "Pending" ? `
                            <div class="review-actions">
                                <button onclick="reviewSubmission(${item.id}, 'approve')">
                                    Approve
                                </button>
                                <button class="delete-btn"
                                    onclick="reviewSubmission(${item.id}, 'reject')">
                                    Reject
                                </button>
                            </div>
                        ` : `
                            <p><strong>Review note:</strong>
                                ${escapeHTML(item.review_note || "None")}
                            </p>
                        `
                }
                </div>
            `;
        }).join("");

    } catch (error) {
        list.innerHTML = `<p>${escapeHTML(error.message)}</p>`;
    }
}


async function reviewSubmission(id, action) {
    const note = prompt("Add a review note (optional):") || "";

    try {
        const response = await fetch(
            `/admin/submissions/${id}/${action}`,
            {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ review_note: note })
            }
        );

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.detail || "Review failed");
        }

        alert(result.message);
        await loadSubmissionCounts();
        await loadSubmissions();
        await loadActivityLog();

    } catch (error) {
        alert(error.message);
    }
}

async function loadActivityLog() {
    const container = document.getElementById("activityList");
    if (!container) return;

    try {
        const activities = await getJSON("/admin/activity");

        if (!activities.length) {
            container.innerHTML = "<p>No administrator activity yet.</p>";
            return;
        }

        container.innerHTML = activities.map(item => `
            <div class="activity-item">
                <strong>${escapeHTML(item.action)}</strong>
                <p>${escapeHTML(item.admin_username)}</p>
                <p>${escapeHTML(item.category || "")}
                    ${item.record_id ? `#${item.record_id}` : ""}
                </p>
                <small>${escapeHTML(item.created_at)}</small>
            </div>
        `).join("");

    } catch (error) {
        console.error(error);
    }
}

document.getElementById("searchInput")?.addEventListener(
    "input", applyFilters
);

document.getElementById("categoryFilter")?.addEventListener(
    "change", applyFilters
);

document.getElementById("severityFilter")?.addEventListener(
    "change", applyFilters
);

document.getElementById("dateFilter")?.addEventListener(
    "change", applyFilters
);

document.getElementById("clearFilters")?.addEventListener("click", () => {
    ["searchInput", "categoryFilter", "severityFilter", "dateFilter"]
        .forEach(id => {
            const element = document.getElementById(id);
            if (element) {
                if (element.tagName === "SELECT") element.value = "All";
                else element.value = "";
            }
        });

    applyFilters();
});

document.getElementById("exportButton")?.addEventListener(
    "click", exportCSV
);

document.getElementById("refreshSubmissions")?.addEventListener(
    "click", async () => {
        await loadSubmissionCounts();
        await loadSubmissions();
    }
);

document.getElementById("submissionStatus")?.addEventListener(
    "change", loadSubmissions
);


document.addEventListener("DOMContentLoaded", async () => {
    await checkAdminStatus();

    if (
        document.getElementById("actorsTable") ||
        document.getElementById("malwareTable") ||
        document.getElementById("iocsTable")
    ) {
        await loadThreatTables();
    }

    if (document.getElementById("actorCount")) {
        await loadDashboard();
    }

    initializeAdminPage();
});