/**
 * Scanner Form Interactivity and Animated Progress Indicators
 */

document.addEventListener("DOMContentLoaded", () => {
  const scanForm = document.getElementById("scanForm");
  const scanBtn = document.getElementById("scanBtn");
  const urlInput = document.getElementById("targetUrl");
  const progressBox = document.getElementById("scanProgressBox");
  const progressText = document.getElementById("scanProgressStep");
  const errorBox = document.getElementById("scanErrorBox");
  const errorMsg = document.getElementById("scanErrorMessage");

  if (!scanForm) return;

  // Preset quick fill links
  document.querySelectorAll(".preset-target").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      const url = btn.getAttribute("data-url");
      if (urlInput && url) {
        urlInput.value = url;
        urlInput.focus();
      }
    });
  });

  scanForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    let rawUrl = (urlInput.value || "").trim();
    if (!rawUrl) {
      showError("Please enter a website URL to assess.");
      return;
    }

    if (!rawUrl.startsWith("http://") && !rawUrl.startsWith("https://")) {
      rawUrl = "https://" + rawUrl;
      urlInput.value = rawUrl;
    }

    // Hide error, show animated progress
    hideError();
    showProgress();

    // Progress animation steps
    const steps = [
      "1/4 Resolving DNS and enforcing SSRF defenses...",
      "2/4 Initiating safe TLS handshake & redirect inspection...",
      "3/4 Parsing X-Frame-Options and CSP frame-ancestors...",
      "4/4 Synthesizing compliance findings and risk posture...",
    ];

    let currentStep = 0;
    const interval = setInterval(() => {
      currentStep++;
      if (currentStep < steps.length && progressText) {
        progressText.innerText = steps[currentStep];
      }
    }, 700);

    try {
      const response = await fetch("/scan/run", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": window.getCSRFToken(),
        },
        body: JSON.stringify({ url: rawUrl }),
      });

      clearInterval(interval);
      const data = await response.json();

      if (response.ok && data.success && data.redirect_url) {
        progressText.innerText = "Assessment complete! Redirecting to report...";
        window.location.href = data.redirect_url;
      } else {
        hideProgress();
        showError(data.error || data.message || "Security scan could not be completed.");
      }
    } catch (err) {
      clearInterval(interval);
      hideProgress();
      showError("Network connection failure or timeout while communicating with scanner engine.");
    }
  });

  function showProgress() {
    if (progressBox) progressBox.classList.remove("d-none");
    if (scanBtn) scanBtn.disabled = true;
    if (urlInput) urlInput.disabled = true;
    if (progressText) progressText.innerText = "1/4 Resolving DNS and enforcing SSRF defenses...";
  }

  function hideProgress() {
    if (progressBox) progressBox.classList.add("d-none");
    if (scanBtn) scanBtn.disabled = false;
    if (urlInput) urlInput.disabled = false;
  }

  function showError(msg) {
    if (errorBox && errorMsg) {
      errorMsg.innerText = msg;
      errorBox.classList.remove("d-none");
    }
  }

  function hideError() {
    if (errorBox) errorBox.classList.add("d-none");
  }
});
