/**
 * ClickjackShield — Rule-Based Cybersecurity Chatbot
 * ====================================================
 * Pure JavaScript keyword-matching chatbot.
 * No external AI APIs. All responses are predefined.
 *
 * Architecture:
 *  - KNOWLEDGE_BASE: Array of {keywords[], answer, quickReplies[]} rules
 *  - matchResponse(input): Finds best matching rule
 *  - ChatbotUI: Manages DOM, chat history, and rendering
 */

/* ─────────────────────────────────────────────────────────────────────────
   KNOWLEDGE BASE  ·  Order matters: more specific rules first
   ───────────────────────────────────────────────────────────────────────── */
const KNOWLEDGE_BASE = [

  /* ── Greetings ─────────────────────────────────────────────────────────── */
  {
    id: "greeting",
    keywords: ["hello", "hi", "hey", "namaste", "namaskar", "good morning", "good evening", "howdy", "greet"],
    answer: `👋 <strong>Hello! Welcome to ClickjackShield Assistant!</strong><br><br>
I am your cybersecurity guide for this platform. I can help you with:
<ul class="chat-list">
  <li>🛡️ Clickjacking attacks &amp; defences</li>
  <li>🔍 Security header analysis (X-Frame-Options, CSP)</li>
  <li>🧪 Using the Scanner &amp; Demo Lab</li>
  <li>📄 Generating security reports</li>
  <li>📚 Prevention &amp; remediation strategies</li>
</ul>
Type your question or pick a topic below!`,
    quickReplies: ["What is clickjacking?", "How to scan a website?", "What is X-Frame-Options?", "What is CSP?"]
  },

  /* ── Clickjacking definition ────────────────────────────────────────────── */
  {
    id: "clickjacking_what",
    keywords: ["clickjacking kya hai", "what is clickjacking", "clickjacking define", "clickjacking meaning", "clickjacking attack kya", "ui redressing", "ui redress", "click hijack"],
    answer: `🎯 <strong>Clickjacking (UI Redressing Attack)</strong><br><br>
Clickjacking ek web security attack hai jisme attacker ek <em>transparent or invisible iframe</em> ke andar victim website ko load karta hai aur uske upar apna deceptive content overlay karta hai.<br><br>
<strong>Simple Example:</strong> User sochta hai wo "Play Video" button click kar raha hai, lekin actually ek invisible bank transfer button click ho jaata hai.<br><br>
<div class="chat-code">
  Visible Layer:  [Fake "Click Here!" button]
  Hidden Layer:   [Real bank "Confirm Transfer" button]
  ↑ User clicks visible, hits hidden!
</div><br>
<strong>Impact:</strong>
<ul class="chat-list">
  <li>Unauthorized fund transfers</li>
  <li>Account settings changes</li>
  <li>Social media actions without consent</li>
  <li>Malware downloads triggered</li>
</ul>`,
    quickReplies: ["How does clickjacking work?", "How to prevent clickjacking?", "What is X-Frame-Options?", "Scan a website now"]
  },

  /* ── How clickjacking works ─────────────────────────────────────────────── */
  {
    id: "clickjacking_how",
    keywords: ["clickjacking kaise kaam", "how clickjacking works", "clickjacking mechanism", "iframe attack", "how does clickjacking", "clickjacking process", "clickjacking example"],
    answer: `⚙️ <strong>Clickjacking Attack Mechanism</strong><br><br>
<strong>Step-by-Step Attack Flow:</strong>
<ol class="chat-list">
  <li><strong>Attacker Setup:</strong> Creates a malicious webpage</li>
  <li><strong>Iframe Embed:</strong> Loads victim's site inside a hidden <code>&lt;iframe&gt;</code></li>
  <li><strong>CSS Manipulation:</strong> Makes iframe transparent (<code>opacity: 0.001</code>) and positions it over fake buttons</li>
  <li><strong>User Visits:</strong> Victim lands on attacker's page</li>
  <li><strong>Click Hijack:</strong> User clicks "visible" button but actually clicks iframe content</li>
</ol>
<div class="chat-code">
&lt;iframe src="https://victim-bank.com/transfer"
  style="opacity:0.001; position:absolute; 
         top:0; left:0; z-index:999"&gt;
&lt;/iframe&gt;
&lt;button style="position:absolute; top:50px"&gt;
  Win a Prize! 🎁
&lt;/button&gt;
</div><br>
ClickjackShield <strong>Demo Lab</strong> mein aap yeh attack live dekh sakte hain!`,
    quickReplies: ["How to prevent clickjacking?", "Open Demo Lab", "What is X-Frame-Options?", "What headers protect against it?"]
  },

  /* ── Prevention ─────────────────────────────────────────────────────────── */
  {
    id: "prevention",
    keywords: ["prevent clickjacking", "clickjacking se kaise bachein", "protection clickjacking", "defend clickjacking", "stop clickjacking", "clickjacking fix", "secure against clickjacking", "clickjacking prevention"],
    answer: `🛡️ <strong>Clickjacking Prevention Methods</strong><br><br>
<strong>1. X-Frame-Options Header (Recommended)</strong>
<div class="chat-code">X-Frame-Options: DENY
X-Frame-Options: SAMEORIGIN</div>

<strong>2. Content Security Policy frame-ancestors</strong>
<div class="chat-code">Content-Security-Policy: frame-ancestors 'none';
Content-Security-Policy: frame-ancestors 'self';</div>

<strong>3. JavaScript Frame-Busting (Legacy — not reliable)</strong>
<div class="chat-code">if (top !== self) { top.location = self.location; }</div>

<strong>4. SameSite Cookie Attribute</strong>
<div class="chat-code">Set-Cookie: session=abc; SameSite=Strict</div>

<strong>Best Practice:</strong> Use <em>both</em> X-Frame-Options AND CSP frame-ancestors for maximum coverage across all browsers.<br><br>
📋 Detailed guide available in <a href="/prevention" class="chat-link">Prevention Guide</a>`,
    quickReplies: ["What is X-Frame-Options?", "What is frame-ancestors?", "What is CSP?", "Scan my website"]
  },

  /* ── X-Frame-Options ────────────────────────────────────────────────────── */
  {
    id: "xfo",
    keywords: ["x-frame-options", "xfo", "x frame options", "deny", "sameorigin", "allowfrom", "frame-options header", "x-frame"],
    answer: `🔧 <strong>X-Frame-Options HTTP Header</strong><br><br>
<strong>RFC 7034</strong> standard header jo browser ko batata hai ki page ko <code>&lt;iframe&gt;</code> mein load karna allowed hai ya nahi.<br><br>
<strong>Valid Values:</strong>
<table class="chat-table">
  <tr><th>Value</th><th>Effect</th></tr>
  <tr><td><code>DENY</code></td><td>Framing completely blocked (most secure)</td></tr>
  <tr><td><code>SAMEORIGIN</code></td><td>Only same-origin sites can frame</td></tr>
  <tr><td><code>ALLOW-FROM uri</code></td><td>Specific origin allowed (deprecated in modern browsers)</td></tr>
</table><br>
<strong>How to Set (Apache):</strong>
<div class="chat-code">Header always set X-Frame-Options "DENY"</div>
<strong>How to Set (Nginx):</strong>
<div class="chat-code">add_header X-Frame-Options "DENY" always;</div>
<strong>Flask / Python:</strong>
<div class="chat-code">response.headers["X-Frame-Options"] = "DENY"</div>

⚠️ <em>ALLOW-FROM is deprecated — use CSP frame-ancestors instead.</em>`,
    quickReplies: ["What is CSP?", "What is frame-ancestors?", "How to prevent clickjacking?", "Scan a website"]
  },

  /* ── CSP general ────────────────────────────────────────────────────────── */
  {
    id: "csp",
    keywords: ["content security policy", "csp kya hai", "what is csp", "content-security-policy", "csp header", "csp policy"],
    answer: `📋 <strong>Content Security Policy (CSP)</strong><br><br>
CSP ek powerful HTTP security header hai jo browser ko batata hai ki webpage kahan se resources load kar sakta hai aur kaise behave karna chahiye.<br><br>
<strong>Clickjacking ke liye key directive:</strong>
<div class="chat-code">Content-Security-Policy: frame-ancestors 'none';</div>

<strong>CSP Directives Overview:</strong>
<table class="chat-table">
  <tr><th>Directive</th><th>Controls</th></tr>
  <tr><td><code>frame-ancestors</code></td><td>Who can embed this page in iframe</td></tr>
  <tr><td><code>default-src</code></td><td>Default resource loading policy</td></tr>
  <tr><td><code>script-src</code></td><td>JavaScript sources allowed</td></tr>
  <tr><td><code>img-src</code></td><td>Image sources allowed</td></tr>
</table><br>
CSP <strong>frame-ancestors</strong> X-Frame-Options se zyada powerful hai aur isse replace karta hai modern browsers mein.`,
    quickReplies: ["What is frame-ancestors?", "X-Frame-Options vs CSP?", "How to set CSP?", "Scan my website"]
  },

  /* ── frame-ancestors ────────────────────────────────────────────────────── */
  {
    id: "frame_ancestors",
    keywords: ["frame-ancestors", "frame ancestors", "frame-ancestors directive", "csp frame", "ancestors directive"],
    answer: `🎯 <strong>CSP frame-ancestors Directive</strong><br><br>
<code>frame-ancestors</code> CSP ka directive hai jo specify karta hai ki kaunse origins is page ko <code>&lt;iframe&gt;</code>, <code>&lt;frame&gt;</code>, <code>&lt;embed&gt;</code>, ya <code>&lt;object&gt;</code> mein embed kar sakte hain.<br><br>
<strong>Examples:</strong>
<div class="chat-code">
# Block all framing (most secure)
Content-Security-Policy: frame-ancestors 'none';

# Allow only same origin
Content-Security-Policy: frame-ancestors 'self';

# Allow specific trusted domain
Content-Security-Policy: frame-ancestors https://trusted.com;

# Allow multiple origins
Content-Security-Policy: frame-ancestors 'self' https://trusted.com;
</div><br>
<strong>frame-ancestors vs X-Frame-Options:</strong>
<ul class="chat-list">
  <li>✅ <code>frame-ancestors</code> — Modern browsers, granular control</li>
  <li>✅ <code>X-Frame-Options</code> — Older browsers support</li>
  <li>💡 Use <strong>both</strong> for maximum compatibility</li>
</ul>`,
    quickReplies: ["What is X-Frame-Options?", "How to prevent clickjacking?", "Scan website", "See Prevention Guide"]
  },

  /* ── XFO vs CSP comparison ──────────────────────────────────────────────── */
  {
    id: "xfo_vs_csp",
    keywords: ["xfo vs csp", "x-frame-options vs csp", "difference xfo csp", "compare xfo csp", "which is better xfo csp", "xfo or csp"],
    answer: `⚖️ <strong>X-Frame-Options vs CSP frame-ancestors</strong><br><br>
<table class="chat-table">
  <tr><th>Feature</th><th>X-Frame-Options</th><th>CSP frame-ancestors</th></tr>
  <tr><td>Browser Support</td><td>All browsers</td><td>Modern browsers</td></tr>
  <tr><td>Granularity</td><td>Limited</td><td>Multiple origins</td></tr>
  <tr><td>ALLOW-FROM</td><td>1 origin only</td><td>Multiple origins ✅</td></tr>
  <tr><td>W3C Standard</td><td>RFC 7034</td><td>CSP Level 2/3 ✅</td></tr>
  <tr><td>Deprecated values</td><td>ALLOW-FROM ⚠️</td><td>None</td></tr>
</table><br>
<strong>🏆 Recommendation:</strong> Set <em>both headers</em>:
<div class="chat-code">X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none';</div>
This ensures protection on all browsers, old and new.`,
    quickReplies: ["How to prevent clickjacking?", "Scan my website", "Show Prevention Guide"]
  },

  /* ── How to scan ────────────────────────────────────────────────────────── */
  {
    id: "how_to_scan",
    keywords: ["website scan kaise", "how to scan", "scan kaise karein", "scan website", "use scanner", "scanning kaise", "scan karo", "website check kaise", "how do i scan"],
    answer: `🔍 <strong>Website Scan Kaise Karein</strong><br><br>
<strong>Step-by-Step Process:</strong>
<ol class="chat-list">
  <li>🔗 Navigation bar mein <strong>"Scanner"</strong> click karein</li>
  <li>📝 Target website ka URL enter karein (e.g. <code>https://example.com</code>)</li>
  <li>⚡ <strong>"Run Security Scan"</strong> button click karein</li>
  <li>⏳ Scanner HTTP headers analyze karega (usually 2-5 seconds)</li>
  <li>📊 Results page mein assessment dekkhein:
    <ul>
      <li>🟢 <strong>Protected</strong> — Headers correctly set hain</li>
      <li>🟡 <strong>Potential Risk</strong> — Headers missing ya misconfigured</li>
      <li>⚪ <strong>Inconclusive</strong> — Headers check nahi ho sake</li>
    </ul>
  </li>
  <li>📄 PDF report generate karein (Results page pe button hai)</li>
</ol>
<strong>⚠️ Important:</strong> Only scan websites you own or have explicit permission to test!`,
    quickReplies: ["Go to Scanner", "What does Protected mean?", "How to download report?", "What is clickjacking?"]
  },

  /* ── Scan results meaning ───────────────────────────────────────────────── */
  {
    id: "scan_results",
    keywords: ["scan results", "protected kya matlab", "potential risk kya", "inconclusive kya", "scan results meaning", "assessment result", "scan outcome", "result meaning"],
    answer: `📊 <strong>Scan Assessment Results Guide</strong><br><br>
<table class="chat-table">
  <tr><th>Result</th><th>Meaning</th><th>Action</th></tr>
  <tr>
    <td><span class="chat-badge chat-badge-green">🟢 Protected</span></td>
    <td>X-Frame-Options ya CSP frame-ancestors correctly configured</td>
    <td>✅ No action needed</td>
  </tr>
  <tr>
    <td><span class="chat-badge chat-badge-yellow">🟡 Potential Risk</span></td>
    <td>Headers missing ya weak configuration</td>
    <td>⚠️ Add/fix headers immediately</td>
  </tr>
  <tr>
    <td><span class="chat-badge chat-badge-gray">⚪ Inconclusive</span></td>
    <td>Server unreachable, HTTPS error, or redirect issue</td>
    <td>🔄 Check URL &amp; retry</td>
  </tr>
</table><br>
<strong>Confidence Levels:</strong>
<ul class="chat-list">
  <li><strong>High</strong> — Both XFO &amp; CSP checked successfully</li>
  <li><strong>Medium</strong> — One header available</li>
  <li><strong>Low</strong> — Limited header information</li>
</ul>`,
    quickReplies: ["How to fix Potential Risk?", "How to prevent clickjacking?", "Download report", "Scan another website"]
  },

  /* ── How to download report ─────────────────────────────────────────────── */
  {
    id: "report_download",
    keywords: ["report download", "pdf report", "security report", "report kaise", "download report", "report generate", "report export", "generate report"],
    answer: `📄 <strong>Security Report Kaise Download Karein</strong><br><br>
<strong>Method 1 — Scan Results Page:</strong>
<ol class="chat-list">
  <li>Koi bhi website scan karein</li>
  <li>Scan Results page pe <strong>"Download PDF Report"</strong> button click karein</li>
  <li>PDF automatically download ho jaayega</li>
</ol>

<strong>Method 2 — History Page:</strong>
<ol class="chat-list">
  <li>Navigation mein <strong>"History"</strong> click karein</li>
  <li>Kisi bhi past scan ke row mein <strong>"Report"</strong> link click karein</li>
  <li>PDF report page khulega jahan se download/print kar sakte hain</li>
</ol>

<strong>Report mein kya hota hai:</strong>
<ul class="chat-list">
  <li>🌐 Target URL &amp; hostname details</li>
  <li>🔒 Security assessment outcome &amp; confidence</li>
  <li>📋 X-Frame-Options status &amp; raw header value</li>
  <li>📋 CSP frame-ancestors status</li>
  <li>🛠️ Specific remediation recommendations</li>
  <li>📅 Scan timestamp &amp; metadata</li>
</ul>`,
    quickReplies: ["How to scan a website?", "View scan history", "What is clickjacking?"]
  },

  /* ── Scan history ───────────────────────────────────────────────────────── */
  {
    id: "history",
    keywords: ["scan history", "history kaise", "past scans", "previous scans", "history dekho", "old scans", "history page", "saved scans"],
    answer: `📜 <strong>Scan History Feature</strong><br><br>
Scan History page mein aap apne sabhi previous security assessments dekh sakte hain.<br><br>
<strong>Features:</strong>
<ul class="chat-list">
  <li>🔍 <strong>Search</strong> — hostname ya URL se filter karein</li>
  <li>🎯 <strong>Filter</strong> — Protected / Potential Risk / Inconclusive ke basis pe</li>
  <li>↕️ <strong>Sort</strong> — Date, Status, ya Hostname se</li>
  <li>📄 <strong>Report</strong> — Har scan ke liye PDF report accessible</li>
  <li>🗑️ <strong>Delete</strong> — Individual scan records remove karein</li>
  <li>⛔ <strong>Clear All</strong> — Poora history clear karein</li>
</ul>

<strong>Access:</strong> Navigation bar → <strong>History</strong> link`,
    quickReplies: ["How to scan a website?", "Download report", "What is clickjacking?"]
  },

  /* ── Demo Lab ───────────────────────────────────────────────────────────── */
  {
    id: "demo_lab",
    keywords: ["demo lab", "lab kya hai", "clickjacking demo", "lab page", "educational lab", "live demo", "demo kaise", "lab kaise use", "interactive lab"],
    answer: `🧪 <strong>Clickjacking Demo Lab</strong><br><br>
Demo Lab ek safe, educational sandbox hai jahan aap clickjacking attack <strong>live demonstrate</strong> kar sakte hain bina kisi real website ko harm kiye.<br><br>
<strong>Lab Scenarios:</strong>
<table class="chat-table">
  <tr><th>Scenario</th><th>Description</th></tr>
  <tr><td>🔴 Unprotected Page</td><td>No security headers — iframe embed works (attack succeeds)</td></tr>
  <tr><td>🟢 Protected Page</td><td>DENY headers set — iframe blocked (attack fails)</td></tr>
</table><br>
<strong>How to use:</strong>
<ol class="chat-list">
  <li>Navigation bar → <strong>"Demo Lab"</strong> click karein</li>
  <li>"Load Unprotected Target" select karein — attack mode dekhein</li>
  <li>"Load Protected Target" select karein — defence mode dekhein</li>
  <li>Visual difference compare karein</li>
</ol>
✅ <em>Completely safe — only local test pages are used.</em>`,
    quickReplies: ["What is clickjacking?", "How does clickjacking work?", "How to prevent it?", "Scan a real website"]
  },

  /* ── Dashboard ──────────────────────────────────────────────────────────── */
  {
    id: "dashboard",
    keywords: ["dashboard kya hai", "what is dashboard", "dashboard features", "security dashboard", "stats dashboard", "metrics dashboard"],
    answer: `📈 <strong>Security Dashboard</strong><br><br>
Dashboard aapko poore scanning activity ka overview deta hai:<br><br>
<strong>Metric Cards:</strong>
<ul class="chat-list">
  <li>📊 Total websites scanned</li>
  <li>🟢 Protected sites count &amp; percentage</li>
  <li>🟡 Potential Risk sites count</li>
  <li>⚪ Inconclusive assessments</li>
</ul>

<strong>Visual Charts (Chart.js):</strong>
<ul class="chat-list">
  <li>🍩 Donut chart — Assessment outcome distribution</li>
  <li>📊 Bar chart — Header adoption rates (XFO vs CSP)</li>
</ul>

<strong>Recent Scans Table:</strong> Last 8 assessments with quick links<br><br>
<strong>Access:</strong> Navigation bar → <strong>Dashboard</strong>`,
    quickReplies: ["How to scan a website?", "View scan history", "What is clickjacking?"]
  },

  /* ── Prevention Guide ───────────────────────────────────────────────────── */
  {
    id: "prevention_guide",
    keywords: ["prevention guide", "guide kya hai", "remediation guide", "fix guide", "how to fix", "security guide", "hardening guide", "configuration guide"],
    answer: `📚 <strong>Prevention Guide</strong><br><br>
Prevention Guide page mein clickjacking protection ke complete implementation examples hain:<br><br>
<strong>Covered Topics:</strong>
<ul class="chat-list">
  <li>🌐 <strong>Apache</strong> — .htaccess &amp; httpd.conf configuration</li>
  <li>🌐 <strong>Nginx</strong> — nginx.conf header settings</li>
  <li>🐍 <strong>Python Flask</strong> — after_request header injection</li>
  <li>☕ <strong>Java / Spring Boot</strong> — Security config</li>
  <li>🟢 <strong>Node.js / Express</strong> — Helmet.js integration</li>
  <li>💻 <strong>PHP</strong> — header() function usage</li>
  <li>🔵 <strong>ASP.NET</strong> — web.config settings</li>
</ul>

Each example includes copy-paste ready code snippets!<br><br>
<strong>Access:</strong> Navigation bar → <strong>Prevention Guide</strong>`,
    quickReplies: ["What is X-Frame-Options?", "What is CSP?", "How to prevent clickjacking?", "Scan a website"]
  },

  /* ── OWASP ──────────────────────────────────────────────────────────────── */
  {
    id: "owasp",
    keywords: ["owasp", "owasp top 10", "owasp clickjacking", "owasp a05", "owasp standard"],
    answer: `🔐 <strong>OWASP &amp; Clickjacking</strong><br><br>
<strong>OWASP (Open Web Application Security Project)</strong> clickjacking ko apni security standards mein include karta hai.<br><br>
<strong>Classification:</strong>
<ul class="chat-list">
  <li>📋 OWASP Top 10 — A05: Security Misconfiguration</li>
  <li>📋 OWASP Testing Guide — OTG-CLIENT-009</li>
  <li>📋 OWASP Cheat Sheet: Clickjacking Defense</li>
</ul>

<strong>OWASP Recommended Defences:</strong>
<ol class="chat-list">
  <li>Set <code>X-Frame-Options: DENY</code></li>
  <li>Set <code>Content-Security-Policy: frame-ancestors 'none'</code></li>
  <li>Avoid JavaScript-only frame-busting (unreliable)</li>
</ol>

ClickjackShield scanner OWASP guidelines ke basis par assessments generate karta hai.`,
    quickReplies: ["What is clickjacking?", "How to prevent it?", "Scan website", "Prevention Guide"]
  },

  /* ── HTTPS & security ───────────────────────────────────────────────────── */
  {
    id: "https",
    keywords: ["https", "ssl", "tls", "certificate", "secure connection", "http vs https"],
    answer: `🔒 <strong>HTTPS &amp; Clickjacking</strong><br><br>
HTTPS (HTTP Secure) website traffic ko encrypt karta hai, lekin <strong>clickjacking directly HTTPS se protect nahi hota</strong>.<br><br>
<strong>Why?</strong>
<ul class="chat-list">
  <li>Clickjacking client-side attack hai — attacker victim ke browser pe kaam karta hai</li>
  <li>HTTPS server-client encryption provide karta hai</li>
  <li>Anti-framing headers (<code>X-Frame-Options</code>, <code>CSP frame-ancestors</code>) specifically iframe attacks rokta hai</li>
</ul>

<strong>ClickjackShield Scanner Note:</strong>
<br>Scanner only HTTPS URLs scan karta hai for security — HTTP URLs ko automatically HTTPS redirect kiya jaata hai.
<br><br>✅ HTTPS + Anti-Framing Headers = Best Protection`,
    quickReplies: ["What is X-Frame-Options?", "What is CSP?", "How to prevent clickjacking?"]
  },

  /* ── Error: site unreachable ────────────────────────────────────────────── */
  {
    id: "scan_error",
    keywords: ["scan error", "scan fail", "website unreachable", "connection error", "timeout", "scan nahi ho raha", "error in scan", "could not connect", "scan failed"],
    answer: `⚠️ <strong>Scan Error Troubleshooting</strong><br><br>
Agar scan fail ho raha hai, to in reasons check karein:<br><br>
<table class="chat-table">
  <tr><th>Error</th><th>Cause</th><th>Fix</th></tr>
  <tr><td>Connection timeout</td><td>Website slow ya down hai</td><td>Baad mein retry karein</td></tr>
  <tr><td>Invalid URL</td><td>URL format galat hai</td><td>https:// include karein</td></tr>
  <tr><td>Security validation failed</td><td>Private IP / localhost detected</td><td>Public URLs hi use karein</td></tr>
  <tr><td>Rate limit exceeded</td><td>Too many scans in 1 minute</td><td>60 seconds wait karein</td></tr>
  <tr><td>SSL/TLS error</td><td>Website ka certificate invalid</td><td>Certificate check karein</td></tr>
</table><br>
<strong>Valid URL Format:</strong>
<div class="chat-code">✅ https://example.com
✅ https://www.example.com/page
❌ http://192.168.1.1  (private IP — blocked)
❌ example.com  (missing https://)
</div>`,
    quickReplies: ["How to scan a website?", "What is rate limit?", "Contact support"]
  },

  /* ── About this app ─────────────────────────────────────────────────────── */
  {
    id: "about_app",
    keywords: ["about app", "what is clickjackshield", "app kya hai", "project kya hai", "is application ke baare mein", "about this tool", "about platform", "ye app kya karta hai"],
    answer: `🛡️ <strong>About ClickjackShield</strong><br><br>
<strong>ClickjackShield</strong> ek specialized cybersecurity web platform hai jo:<br><br>
<ul class="chat-list">
  <li>🔍 Websites ke HTTP security headers scan karta hai</li>
  <li>📊 X-Frame-Options &amp; CSP frame-ancestors analyze karta hai</li>
  <li>🧪 Clickjacking attacks ko safely demonstrate karta hai</li>
  <li>📄 PDF security reports generate karta hai</li>
  <li>📚 Developers ko prevention techniques sikhata hai</li>
  <li>🤖 Rule-based chatbot cybersecurity guidance deta hai</li>
</ul>

<strong>Technology Stack:</strong>
<ul class="chat-list">
  <li>Backend: Python Flask + SQLite</li>
  <li>Frontend: Bootstrap 5 + Chart.js</li>
  <li>Scanner: Python requests + header analysis engine</li>
  <li>Chatbot: JavaScript keyword matching (no AI API)</li>
</ul>

<strong>Standards:</strong> RFC 7034 · W3C CSP Level 3 · OWASP Top 10`,
    quickReplies: ["How to scan a website?", "What is clickjacking?", "How to use Demo Lab?"]
  },

  /* ── Thank you / bye ────────────────────────────────────────────────────── */
  {
    id: "goodbye",
    keywords: ["thanks", "thank you", "shukriya", "dhanyawad", "bye", "goodbye", "alvida", "great", "helpful", "awesome", "good job"],
    answer: `😊 <strong>Khushi hui aapki help karke!</strong><br><br>
Koi bhi security question ho to main yahan hoon. Stay safe online! 🛡️<br><br>
<strong>Quick Links:</strong>
<ul class="chat-list">
  <li><a href="/scanner" class="chat-link">🔍 Run a Security Scan</a></li>
  <li><a href="/dashboard" class="chat-link">📊 View Dashboard</a></li>
  <li><a href="/prevention" class="chat-link">📚 Prevention Guide</a></li>
  <li><a href="/lab" class="chat-link">🧪 Demo Lab</a></li>
</ul>`,
    quickReplies: ["What is clickjacking?", "Scan a website", "Prevention Guide"]
  },

];

/* ─────────────────────────────────────────────────────────────────────────
   FALLBACK RESPONSE
   ───────────────────────────────────────────────────────────────────────── */
const FALLBACK_RESPONSE = {
  answer: `🤔 <strong>Mujhe yeh samajh nahi aaya, lekin main help karna chahta hoon!</strong><br><br>
Aap in topics ke baare mein pooch sakte hain:
<ul class="chat-list">
  <li>🎯 Clickjacking attack kya hai?</li>
  <li>🛡️ X-Frame-Options header</li>
  <li>📋 Content Security Policy (CSP)</li>
  <li>🔍 Website scan kaise karein?</li>
  <li>📄 Security report download karna</li>
  <li>🧪 Demo Lab kaise use karein?</li>
  <li>📚 Prevention Guide</li>
</ul>
Ya neeche diye quick reply buttons use karein! 👇`,
  quickReplies: ["What is clickjacking?", "How to scan?", "X-Frame-Options", "CSP frame-ancestors"]
};

/* ─────────────────────────────────────────────────────────────────────────
   KEYWORD MATCHING ENGINE
   ───────────────────────────────────────────────────────────────────────── */
function matchResponse(userInput) {
  const input = userInput.toLowerCase().trim();
  
  if (!input) return FALLBACK_RESPONSE;

  let bestMatch = null;
  let bestScore = 0;

  for (const rule of KNOWLEDGE_BASE) {
    let score = 0;
    for (const keyword of rule.keywords) {
      if (input.includes(keyword.toLowerCase())) {
        // Longer keyword matches = higher specificity score
        score += keyword.length + (input === keyword.toLowerCase() ? 10 : 0);
      }
    }
    if (score > bestScore) {
      bestScore = score;
      bestMatch = rule;
    }
  }

  return bestScore > 0 ? bestMatch : FALLBACK_RESPONSE;
}

// Expose to window for page-level access
window.KNOWLEDGE_BASE = KNOWLEDGE_BASE;
window.matchResponse = matchResponse;
window.FALLBACK_RESPONSE = FALLBACK_RESPONSE;

/* ─────────────────────────────────────────────────────────────────────────
   CHATBOT UI CONTROLLER
   ───────────────────────────────────────────────────────────────────────── */
class ChatbotUI {
  constructor() {
    this.isOpen = false;
    this.messageCount = 0;
    this.typingDelay = 700; // ms — simulate "thinking"

    this.widget      = document.getElementById("chatbot-widget");
    this.toggle      = document.getElementById("chatbot-toggle");
    this.closeBtn    = document.getElementById("chatbot-close");
    this.messagesEl  = document.getElementById("chatbot-messages");
    this.inputEl     = document.getElementById("chatbot-input");
    this.sendBtn     = document.getElementById("chatbot-send");
    this.badge       = document.getElementById("chatbot-badge");

    if (!this.widget) return; // chatbot not mounted on this page

    this._bindEvents();
    this._initWelcome();
  }

  /* ── Events ────────────────────────────────────────────────────────────── */
  _bindEvents() {
    this.toggle.addEventListener("click", () => this.toggleChat());
    this.closeBtn.addEventListener("click", () => this.closeChat());

    this.sendBtn.addEventListener("click", () => this._handleSend());
    this.inputEl.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        this._handleSend();
      }
    });

    // Close on backdrop click
    document.addEventListener("click", (e) => {
      if (this.isOpen && !this.widget.contains(e.target) && !this.toggle.contains(e.target)) {
        this.closeChat();
      }
    });
  }

  /* ── Welcome message ───────────────────────────────────────────────────── */
  _initWelcome() {
    setTimeout(() => {
      const welcome = KNOWLEDGE_BASE.find(r => r.id === "greeting");
      if (welcome) this._appendBot(welcome.answer, welcome.quickReplies);
    }, 300);
  }

  /* ── Toggle ────────────────────────────────────────────────────────────── */
  toggleChat() {
    this.isOpen ? this.closeChat() : this.openChat();
  }

  openChat() {
    this.isOpen = true;
    this.widget.classList.add("chatbot-open");
    this.badge.style.display = "none";
    this.inputEl.focus();
    this._scrollToBottom();
  }

  closeChat() {
    this.isOpen = false;
    this.widget.classList.remove("chatbot-open");
  }

  /* ── Handle user send ──────────────────────────────────────────────────── */
  _handleSend() {
    const text = this.inputEl.value.trim();
    if (!text) return;

    this.inputEl.value = "";
    this._appendUser(text);
    this._showTyping();

    setTimeout(() => {
      this._removeTyping();
      const response = matchResponse(text);
      this._appendBot(response.answer, response.quickReplies);
    }, this.typingDelay);
  }

  /* ── Append messages ───────────────────────────────────────────────────── */
  _appendUser(text) {
    const div = document.createElement("div");
    div.className = "chat-msg chat-msg-user";
    div.innerHTML = `<div class="chat-bubble chat-bubble-user">${this._escapeHtml(text)}</div>`;
    this.messagesEl.appendChild(div);
    this._scrollToBottom();
    this.messageCount++;
  }

  _appendBot(html, quickReplies = []) {
    const wrapper = document.createElement("div");
    wrapper.className = "chat-msg chat-msg-bot";

    const avatar = `<div class="chat-avatar"><i class="fa-solid fa-shield-halved"></i></div>`;
    const bubble = `<div class="chat-bubble chat-bubble-bot">${html}</div>`;

    let qrHtml = "";
    if (quickReplies && quickReplies.length > 0) {
      const buttons = quickReplies
        .map(qr => `<button class="chat-qr-btn" data-qr="${this._escapeAttr(qr)}">${qr}</button>`)
        .join("");
      qrHtml = `<div class="chat-qr-group">${buttons}</div>`;
    }

    wrapper.innerHTML = `${avatar}<div class="chat-bot-content">${bubble}${qrHtml}</div>`;

    // Bind quick reply clicks
    wrapper.querySelectorAll(".chat-qr-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        const qr = btn.getAttribute("data-qr");
        this.inputEl.value = qr;
        this._handleSend();
      });
    });

    this.messagesEl.appendChild(wrapper);
    this._scrollToBottom();

    // Show badge if chat closed
    if (!this.isOpen) {
      this.badge.style.display = "flex";
      this.badge.textContent = "1";
    }
  }

  /* ── Typing indicator ──────────────────────────────────────────────────── */
  _showTyping() {
    const div = document.createElement("div");
    div.id = "chat-typing";
    div.className = "chat-msg chat-msg-bot";
    div.innerHTML = `
      <div class="chat-avatar"><i class="fa-solid fa-shield-halved"></i></div>
      <div class="chat-bubble chat-bubble-bot chat-typing-dots">
        <span></span><span></span><span></span>
      </div>`;
    this.messagesEl.appendChild(div);
    this._scrollToBottom();
  }

  _removeTyping() {
    const el = document.getElementById("chat-typing");
    if (el) el.remove();
  }

  /* ── Utility ───────────────────────────────────────────────────────────── */
  _scrollToBottom() {
    requestAnimationFrame(() => {
      this.messagesEl.scrollTop = this.messagesEl.scrollHeight;
    });
  }

  _escapeHtml(str) {
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  _escapeAttr(str) {
    return str.replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }
}

/* ─────────────────────────────────────────────────────────────────────────
   INIT
   ───────────────────────────────────────────────────────────────────────── */
document.addEventListener("DOMContentLoaded", () => {
  window._chatbotUI = new ChatbotUI();
});
