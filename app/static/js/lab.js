/**
 * Educational Clickjacking Demonstration Lab Controller
 */

document.addEventListener("DOMContentLoaded", () => {
  const targetFrame = document.getElementById("labFrame");
  const opacitySlider = document.getElementById("opacitySlider");
  const opacityValue = document.getElementById("opacityVal");
  const decoyButton = document.getElementById("attackerDecoyBtn");
  const targetSelect = document.getElementById("targetSelect");
  const logContainer = document.getElementById("labEventLog");
  const resetBtn = document.getElementById("labResetBtn");
  const headerDetailsBox = document.getElementById("labHeaderDetails");
  const blockedBanner = document.getElementById("blockedBanner");

  if (!targetFrame) return;

  // Header explanation presets
  const headersMap = {
    unprotected: {
      url: "/lab/demo-target-unprotected",
      xfo: "None (Missing)",
      csp: "None (Missing frame-ancestors)",
      result: "Framing Permitted",
      explanation:
        "The server returns NO anti-framing headers. The browser freely embeds the page into an external iframe, allowing an attacker to redress UI elements.",
    },
    protected: {
      url: "/lab/demo-target-protected",
      xfo: "DENY",
      csp: "frame-ancestors 'none';",
      result: "Framing Blocked by Browser",
      explanation:
        "The server sends 'Content-Security-Policy: frame-ancestors none' and 'X-Frame-Options: DENY'. Modern web browsers refuse to render the framed content, completely stopping the clickjacking attack.",
    },
  };

  // 1. Target Selector Change
  if (targetSelect) {
    targetSelect.addEventListener("change", (e) => {
      const mode = e.target.value;
      switchTarget(mode);
    });
  }

  function switchTarget(mode) {
    const info = headersMap[mode];
    if (!info) return;

    if (mode === "protected") {
      // Show blocked state
      targetFrame.src = info.url;
      // In many browsers, iframes blocked by CSP don't fire onerror, but display a browser refused connection page.
      // We update the inspector and explain:
      if (blockedBanner) blockedBanner.classList.remove("d-none");
      addLogEntry(`Loaded Target B (Protected). Browser receives headers: CSP frame-ancestors 'none' & X-Frame-Options: DENY.`, "info");
      addLogEntry(`Framing is BLOCKED by browser policy. UI redressing cannot occur.`, "success");
    } else {
      if (blockedBanner) blockedBanner.classList.add("d-none");
      targetFrame.src = info.url;
      addLogEntry(`Loaded Target A (Unprotected). Missing anti-framing protections. Framing succeeded.`, "warning");
    }

    updateHeaderDetails(info);
  }

  // 2. Opacity Slider
  if (opacitySlider && opacityValue) {
    opacitySlider.addEventListener("input", (e) => {
      const val = e.target.value;
      opacityValue.innerText = `${val}%`;
      // We adjust the framed page's opacity so the user can see how redressing works
      const decimalOpacity = val / 100;
      targetFrame.style.opacity = decimalOpacity;

      if (val === "0") {
        addLogEntry("Victim iframe set to 0% opacity (Totally Invisible). Attacker decoy completely masks victim UI.", "danger");
      } else if (val === "100") {
        addLogEntry("Victim iframe set to 100% opacity (Fully Visible). Underneath buttons are exposed.", "info");
      }
    });
  }

  // 3. Simulated Click on Decoy Overlay
  if (decoyButton) {
    decoyButton.addEventListener("click", async (e) => {
      const mode = targetSelect ? targetSelect.value : "unprotected";
      const currentOpacity = opacitySlider ? opacitySlider.value : "30";

      if (mode === "protected") {
        addLogEntry("Click landed on decoy, but underlying page could not be framed (Protected). No action triggered on target.", "success");
        return;
      }

      // Attacker decoy tricked the user into clicking!
      addLogEntry(
        `[CLICKJACK TRIGGERED] User intended to click 'Claim $1,000 Reward Voucher' at opacity ${currentOpacity}%. ` +
        `In a real attack, mouse coordinates align with the underlying victim 'Confirm Harmless Transfer' action!`,
        "danger"
      );

      // Harmless mock state-change request to backend
      try {
        const resp = await fetch("/lab/demo-action", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ action: "intercepted_click_redress" }),
        });
        const data = await resp.json();
        addLogEntry(`Simulated Backend Result: ${data.message}`, "warning");
      } catch (err) {
        // Mock fallback
      }
    });
  }

  // 4. Log helper
  function addLogEntry(text, type = "info") {
    if (!logContainer) return;
    const time = new Date().toLocaleTimeString();
    const entry = document.createElement("div");
    entry.className = `p-2 mb-2 rounded font-monospace small ${getLogClass(type)}`;
    entry.innerHTML = `<span class="opacity-75">[${time}]</span> ${text}`;
    logContainer.prepend(entry);
  }

  function getLogClass(type) {
    switch (type) {
      case "danger":
        return "bg-danger bg-opacity-25 text-danger border border-danger border-opacity-50";
      case "success":
        return "bg-success bg-opacity-25 text-success border border-success border-opacity-50";
      case "warning":
        return "bg-warning bg-opacity-25 text-warning border border-warning border-opacity-50";
      default:
        return "bg-secondary bg-opacity-25 text-info border border-info border-opacity-25";
    }
  }

  function updateHeaderDetails(info) {
    if (!headerDetailsBox) return;
    headerDetailsBox.innerHTML = `
      <div class="row g-2">
        <div class="col-md-6">
          <small class="text-dim d-block">X-Frame-Options</small>
          <code class="code-badge">${info.xfo}</code>
        </div>
        <div class="col-md-6">
          <small class="text-dim d-block">Content-Security-Policy</small>
          <code class="code-badge">${info.csp}</code>
        </div>
        <div class="col-12 mt-2">
          <small class="text-dim d-block">Browser Behavior</small>
          <p class="mb-0 small text-light">${info.explanation}</p>
        </div>
      </div>
    `;
  }

  // 5. Reset Lab
  if (resetBtn) {
    resetBtn.addEventListener("click", () => {
      if (targetSelect) targetSelect.value = "unprotected";
      if (opacitySlider) opacitySlider.value = "35";
      if (opacityValue) opacityValue.innerText = "35%";
      if (targetFrame) targetFrame.style.opacity = "0.35";
      if (logContainer) logContainer.innerHTML = "";
      if (blockedBanner) blockedBanner.classList.add("d-none");
      switchTarget("unprotected");
      addLogEntry("Educational Lab reset to initial baseline state.", "info");
    });
  }

  // Initialize with Unprotected
  switchTarget("unprotected");
});
