let eventChart = null;

document.addEventListener("DOMContentLoaded", () => {
    initChart();
    refreshDashboard();
    setInterval(refreshDashboard, 5000);
});

function initChart() {
    const ctx = document.getElementById("eventChart").getContext("2d");
    eventChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Threat Alerts Timeline',
                data: [],
                borderColor: '#00e5ff',
                backgroundColor: 'rgba(0, 229, 255, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.3
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { color: '#1e293b' }, ticks: { color: '#94a3b8' } },
                y: { grid: { color: '#1e293b' }, ticks: { color: '#94a3b8', precision: 0 } }
            }
        }
    });
}

function refreshDashboard() {
    fetchStats();
    fetchAlerts();
    fetchSuspiciousIPs();
}

function fetchStats() {
    fetch('/api/stats')
        .then(res => res.json())
        .then(data => {
            document.getElementById("stat-total").innerText = data.total_events || 0;
            document.getElementById("stat-unique-ips").innerText = data.unique_ips || 0;
            document.getElementById("stat-active").innerText = data.active_threats || 0;
            document.getElementById("stat-high").innerText = data.high_severity || 0;
            
            const badge = document.getElementById("mode-badge");
            const captureText = document.getElementById("capture-status-text");
            if (data.capture_status) {
                captureText.innerText = data.capture_status;
                if (data.capture_status.includes("Live")) {
                    badge.innerText = "Live Capture Active";
                    badge.style.borderColor = "var(--success)";
                    badge.style.color = "var(--success)";
                } else {
                    badge.innerText = "Simulated Mode";
                    badge.style.borderColor = "var(--accent-cyan)";
                    badge.style.color = "var(--accent-cyan)";
                }
            }
        })
        .catch(err => console.error("Error fetching stats:", err));
}

function fetchAlerts() {
    fetch('/api/alerts')
        .then(res => res.json())
        .then(data => {
            const tbody = document.getElementById("alerts-tbody");
            tbody.innerHTML = "";
            if (data.length === 0) {
                tbody.innerHTML = `<tr><td colspan="6" class="text-center">No alerts recorded yet. Use simulation buttons above.</td></tr>`;
                updateChart([]);
                return;
            }

            data.forEach(alert => {
                const tr = document.createElement("tr");
                const sevClass = `severity-${alert.severity.toLowerCase()}`;
                tr.innerHTML = `
                    <td>${alert.timestamp}</td>
                    <td>${alert.src_ip}</td>
                    <td>${alert.dst_ip}</td>
                    <td>${alert.attack_type}</td>
                    <td class="${sevClass}">${alert.severity}</td>
                    <td>${alert.status}</td>
                `;
                tbody.appendChild(tr);
            });

            updateChart(data);
        })
        .catch(err => console.error("Error fetching alerts:", err));
}

function fetchSuspiciousIPs() {
    fetch('/api/suspicious_ips')
        .then(res => res.json())
        .then(data => {
            const tbody = document.getElementById("suspicious-tbody");
            tbody.innerHTML = "";
            if (data.length === 0) {
                tbody.innerHTML = `<tr><td colspan="3" class="text-center">No suspicious IPs flagged.</td></tr>`;
                return;
            }

            data.forEach(item => {
                const tr = document.createElement("tr");
                tr.innerHTML = `
                    <td>${item.src_ip}</td>
                    <td>${item.attack_count}</td>
                    <td>${item.max_severity}</td>
                `;
                tbody.appendChild(tr);
            });
        })
        .catch(err => console.error("Error fetching suspicious IPs:", err));
}

function updateChart(alerts) {
    const chronological = [...alerts].reverse();
    const labels = chronological.map(a => a.timestamp.split(" ")[1] || a.timestamp);
    const dataPoints = chronological.map((_, index) => index + 1);

    eventChart.data.labels = labels;
    eventChart.data.datasets[0].data = dataPoints;
    eventChart.update();
}

function triggerSimulation(type) {
    fetch(`/api/simulate/${type}`, { method: 'POST' })
        .then(res => res.json())
        .then(data => { refreshDashboard(); })
        .catch(err => console.error("Simulation error:", err));
}

function clearData() {
    if (!confirm("Are you sure you want to clear all demo data and logs?")) return;
    fetch('/api/clear_data', { method: 'POST' })
        .then(res => res.json())
        .then(data => { refreshDashboard(); })
        .catch(err => console.error("Clear data error:", err));
}

function startLiveCapture() {
    fetch('/api/capture/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
    })
    .then(res => res.json())
    .then(data => {
        alert(data.message);
        refreshDashboard();
    })
    .catch(err => console.error("Start capture error:", err));
}

function stopLiveCapture() {
    fetch('/api/capture/stop', { method: 'POST' })
        .then(res => res.json())
        .then(data => {
            alert(data.message);
            refreshDashboard();
        })
        .catch(err => console.error("Stop capture error:", err));
}