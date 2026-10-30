/**
 * Dashboard Chart.js Visualizations
 */

document.addEventListener("DOMContentLoaded", () => {
  const chartCanvas = document.getElementById("postureChart");
  if (!chartCanvas) return;

  const total = parseInt(chartCanvas.getAttribute("data-total") || "0", 10);
  const protectedCount = parseInt(chartCanvas.getAttribute("data-protected") || "0", 10);
  const riskCount = parseInt(chartCanvas.getAttribute("data-risk") || "0", 10);
  const inconclusiveCount = parseInt(chartCanvas.getAttribute("data-inconclusive") || "0", 10);

  // If there are no scans yet, render a subtle placeholder distribution
  const dataValues = total > 0 ? [protectedCount, riskCount, inconclusiveCount] : [0, 0, 1];
  const backgroundColors = total > 0
    ? ["#34d399", "#fbbf24", "#6b7280"]
    : ["#1e1035", "#1e1035", "#2d1f4a"];
  const labels = total > 0
    ? ["Protected", "Potential Risk", "Inconclusive"]
    : ["No Data Available", "", ""];

  new Chart(chartCanvas, {
    type: "doughnut",
    data: {
      labels: labels,
      datasets: [
        {
          data: dataValues,
          backgroundColor: backgroundColors,
          borderColor: "#0f172a",
          borderWidth: 3,
          hoverOffset: 6,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "bottom",
          labels: {
            color: "#94a3b8",
            font: {
              family: "'Inter', sans-serif",
              size: 12,
            },
            padding: 18,
            usePointStyle: true,
          },
        },
        tooltip: {
          backgroundColor: "#160e28",
          titleColor: "#f0edfb",
          bodyColor: "#9d8ec4",
          borderColor: "#3d2666",
          borderWidth: 1,
          padding: 10,
        },
      },
      cutout: "68%",
    },
  });

  // Secondary bar chart for mechanisms if present
  const mechCanvas = document.getElementById("mechanismsChart");
  if (mechCanvas) {
    const xfoCount = parseInt(mechCanvas.getAttribute("data-xfo") || "0", 10);
    const cspCount = parseInt(mechCanvas.getAttribute("data-csp") || "0", 10);
    const bothCount = parseInt(mechCanvas.getAttribute("data-both") || "0", 10);

    new Chart(mechCanvas, {
      type: "bar",
      data: {
        labels: ["X-Frame-Options", "CSP frame-ancestors", "Both (Multi-Layered)"],
        datasets: [
          {
            label: "Detected Implementations",
            data: [xfoCount, cspCount, bothCount],
            backgroundColor: ["#b06afc", "#818cf8", "#34d399"],
            borderRadius: 6,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: {
            beginAtZero: true,
            ticks: {
              color: "#94a3b8",
              precision: 0,
            },
            grid: {
              color: "rgba(51, 65, 85, 0.4)",
            },
          },
          x: {
            ticks: {
              color: "#94a3b8",
            },
            grid: {
              display: false,
            },
          },
        },
        plugins: {
          legend: {
            display: false,
          },
        },
      },
    });
  }
});
