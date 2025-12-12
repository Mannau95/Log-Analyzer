// web_app/static/js/dashboard.js
document.addEventListener("DOMContentLoaded", function () {
  // Initialisation des graphiques
  let alertsByTypeChart = null;
  let severityChart = null;
  let topIpsChart = null;
  let timelineChart = null;

  // Mettre à jour les statistiques
  function updateStats() {
    fetch("/api/stats")
      .then((response) => response.json())
      .then((data) => {
        // Mettre à jour les compteurs
        document.getElementById("files-count").textContent =
          data.files_processed || 0;
        document.getElementById("lines-count").textContent =
          data.total_lines || 0;
        document.getElementById("alerts-total").textContent =
          data.total_alerts || 0;
        document.getElementById("high-alerts").textContent =
          data.alerts_by_severity?.high || 0;

        // Mettre à jour le compteur dans la navbar
        document.getElementById("alert-count").textContent = `${
          data.total_alerts || 0
        } alertes`;

        // Graphique des types d'alertes
        updateAlertsByTypeChart(data.alerts_by_type || {});

        // Graphique de sévérité
        updateSeverityChart(data.alerts_by_severity || {});

        // Graphique des IPs
        updateTopIpsChart(data.top_ips || {});

        // Charger les alertes récentes
        loadRecentAlerts();
      })
      .catch((error) => console.error("Erreur:", error));
  }

  function updateAlertsByTypeChart(data) {
    const ctx = document.getElementById("alertsByTypeChart").getContext("2d");
    const labels = Object.keys(data);
    const values = Object.values(data);

    if (alertsByTypeChart) {
      alertsByTypeChart.destroy();
    }

    alertsByTypeChart = new Chart(ctx, {
      type: "bar",
      data: {
        labels: labels,
        datasets: [
          {
            label: "Nombre d'alertes",
            data: values,
            backgroundColor: [
              "#ff6384",
              "#36a2eb",
              "#ffce56",
              "#4bc0c0",
              "#9966ff",
              "#ff9f40",
              "#8ac926",
              "#1982c4",
            ],
            borderWidth: 1,
          },
        ],
      },
      options: {
        responsive: true,
        plugins: {
          legend: {
            display: false,
          },
        },
        scales: {
          y: {
            beginAtZero: true,
            ticks: {
              stepSize: 1,
            },
          },
        },
      },
    });
  }

  function updateSeverityChart(data) {
    const ctx = document.getElementById("severityChart").getContext("2d");
    const labels = ["High", "Medium", "Low"];
    const values = [data.high || 0, data.medium || 0, data.low || 0];
    const backgroundColors = ["#dc3545", "#ffc107", "#28a745"];

    if (severityChart) {
      severityChart.destroy();
    }

    severityChart = new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: labels,
        datasets: [
          {
            data: values,
            backgroundColor: backgroundColors,
            borderWidth: 2,
            borderColor: "#fff",
          },
        ],
      },
      options: {
        responsive: true,
        plugins: {
          legend: {
            position: "bottom",
          },
        },
      },
    });
  }

  function updateTopIpsChart(data) {
    const ctx = document.getElementById("topIpsChart").getContext("2d");
    const labels = Object.keys(data).slice(0, 10);
    const values = Object.values(data).slice(0, 10);

    if (topIpsChart) {
      topIpsChart.destroy();
    }

    topIpsChart = new Chart(ctx, {
      type: "horizontalBar",
      data: {
        labels: labels,
        datasets: [
          {
            label: "Alertes",
            data: values,
            backgroundColor: "#3b82f6",
            borderWidth: 1,
          },
        ],
      },
      options: {
        indexAxis: "y",
        responsive: true,
        plugins: {
          legend: {
            display: false,
          },
        },
      },
    });
  }

  function loadRecentAlerts() {
    fetch("/api/alerts?per_page=5")
      .then((response) => response.json())
      .then((data) => {
        const container = document.getElementById("recent-alerts");

        if (data.alerts.length === 0) {
          container.innerHTML = `
                        <div class="text-center text-muted my-5">
                            <i class="bi bi-inbox fs-1"></i>
                            <p>Aucune alerte pour le moment</p>
                            <a href="/upload" class="btn btn-primary">
                                <i class="bi bi-upload"></i> Analyser des logs
                            </a>
                        </div>
                    `;
          return;
        }

        let html = "";
        data.alerts.forEach((alert) => {
          const severityClass = `severity-${alert.severity}`;
          const icon = getAlertIcon(alert.type);

          html += `
                        <div class="alert-card alert alert-${
                          alert.severity
                        } d-flex align-items-center">
                            <div class="alert-icon">${icon}</div>
                            <div class="flex-grow-1">
                                <div class="d-flex justify-content-between">
                                    <strong>${alert.type}</strong>
                                    <span class="badge ${severityClass}">${alert.severity.toUpperCase()}</span>
                                </div>
                                <div class="mt-1">${alert.message}</div>
                                <div class="timestamp mt-1">
                                    <i class="bi bi-clock"></i> ${alert.timestamp.substring(
                                      11,
                                      16
                                    )}
                                </div>
                            </div>
                        </div>
                    `;
        });

        container.innerHTML = html;
      });
  }

  function getAlertIcon(type) {
    const icons = {
      SSH: "🔐",
      WEB: "🌐",
      SQL: "💾",
      XSS: "⚠️",
      BRUTEFORCE: "🔨",
      SCAN: "🔍",
      WINDOWS: "🪟",
      default: "🚨",
    };

    for (const [key, icon] of Object.entries(icons)) {
      if (type.includes(key)) {
        return icon;
      }
    }
    return icons.default;
  }

  // Actualiser toutes les 30 secondes
  updateStats();
  setInterval(updateStats, 30000);

  // Initialiser le graphique de timeline (simplifié)
  const timelineCtx = document.getElementById("timelineChart").getContext("2d");
  timelineChart = new Chart(timelineCtx, {
    type: "line",
    data: {
      labels: ["00:00", "04:00", "08:00", "12:00", "16:00", "20:00"],
      datasets: [
        {
          label: "Alertes par heure",
          data: [12, 19, 3, 5, 2, 3],
          borderColor: "#667eea",
          backgroundColor: "rgba(102, 126, 234, 0.1)",
          fill: true,
          tension: 0.4,
        },
      ],
    },
    options: {
      responsive: true,
      plugins: {
        legend: {
          display: false,
        },
      },
    },
  });
});
