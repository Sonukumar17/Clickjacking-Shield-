/**
 * ClickjackShield Main JavaScript Utilities
 */

document.addEventListener("DOMContentLoaded", () => {
  // 1. Setup CSRF Token Helper
  window.getCSRFToken = function () {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") : "";
  };

  // 2. Attach Global CSRF Token to Fetch Requests
  const originalFetch = window.fetch;
  window.fetch = function (url, options = {}) {
    options.headers = options.headers || {};
    if (!options.headers["X-CSRF-Token"] && window.getCSRFToken()) {
      options.headers["X-CSRF-Token"] = window.getCSRFToken();
    }
    return originalFetch(url, options);
  };

  // 3. Code Block Copy to Clipboard
  document.querySelectorAll(".copy-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const targetId = btn.getAttribute("data-target");
      const targetEl = targetId ? document.getElementById(targetId) : btn.parentElement;
      const textToCopy = targetEl.innerText.replace("Copy", "").trim();

      navigator.clipboard.writeText(textToCopy).then(() => {
        const originalText = btn.innerHTML;
        btn.innerHTML = '<i class="fa-solid fa-check text-success"></i> Copied!';
        setTimeout(() => {
          btn.innerHTML = originalText;
        }, 2000);
      });
    });
  });

  // 4. Auto-dismiss Bootstrap flash alerts after 6 seconds
  document.querySelectorAll(".alert-dismissible").forEach((alertEl) => {
    setTimeout(() => {
      try {
        const bsAlert = new bootstrap.Alert(alertEl);
        bsAlert.close();
      } catch (e) {
        // Ignored if manually closed
      }
    }, 6000);
  });
});
