// Helper: Escape HTML special characters for safe DOM insertion
function escapeHtml(value) {
  if (value === null || value === undefined) return "";
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Helper: Render a Tabler icon from the inline SVG sprite
function tablerIcon(id, sizeClass) {
  const cls = sizeClass ? `icon ${sizeClass}` : "icon";
  const dim = sizeClass === "icon-small" ? 16 : sizeClass === "icon-large" ? 24 : 20;
  return `<svg class="${cls}" aria-hidden="true" width="${dim}" height="${dim}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><use href="#${id}"></use></svg>`;
}

// Helper: Parse certificate date components from string
function parseCertDateComponents(certDateStr) {
  if (!certDateStr || certDateStr.length < 13) return null;

  let year, month, day, hour, minute, second;

  // Check if it's UTCTime format (YYMMDDhhmmssZ)
  if (certDateStr.length === 13 && certDateStr.endsWith("Z")) {
    const yearPrefix = parseInt(certDateStr.substring(0, 2), 10) >= 50 ? "19" : "20";
    year = yearPrefix + certDateStr.substring(0, 2);
    month = parseInt(certDateStr.substring(2, 4), 10) - 1; // 0-based month
    day = certDateStr.substring(4, 6);
    hour = certDateStr.substring(6, 8);
    minute = certDateStr.substring(8, 10);
    second = certDateStr.substring(10, 12);
  }
  // GeneralizedTime format (YYYYMMDDhhmmssZ)
  else {
    year = certDateStr.substring(0, 4);
    month = parseInt(certDateStr.substring(4, 6), 10) - 1; // 0-based month
    day = certDateStr.substring(6, 8);
    hour = certDateStr.substring(8, 10);
    minute = certDateStr.substring(10, 12);
    second = certDateStr.substring(12, 14);
  }

  return { year, month, day, hour, minute, second };
}

// Helper: Format certificate dates to standard format (MMM DD HH:MM:SS YYYY GMT)
function formatDate(certDateStr) {
  const components = parseCertDateComponents(certDateStr);
  if (!components) return certDateStr;

  const months = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
  ];

  return `${months[components.month]} ${parseInt(components.day, 10)} ${components.hour}:${components.minute}:${components.second} ${components.year} GMT`;
}

// Helper: Parse certificate date string to Date object
function parseCertDate(certDateStr) {
  const components = parseCertDateComponents(certDateStr);
  if (!components) return null;

  return new Date(Date.UTC(
    components.year,
    components.month,
    parseInt(components.day, 10),
    components.hour,
    components.minute,
    components.second
  ));
}

// Helper: Compute current certificate validity status
function getValidityStatus(notBeforeDate, notAfterDate) {
  if (!notBeforeDate || !notAfterDate) return null;
  const now = new Date();
  if (now < notBeforeDate) {
    return { label: "Not yet valid", className: "uvy-status uvy-status--info" };
  }
  if (now > notAfterDate) {
    return { label: "Expired", className: "uvy-status uvy-status--danger" };
  }
  const daysRemaining = Math.ceil((notAfterDate - now) / (1000 * 60 * 60 * 24));
  if (daysRemaining <= 30) {
    return { label: `Expiring in ${daysRemaining}d`, className: "uvy-status uvy-status--warn" };
  }
  return { label: "Valid", className: "uvy-status uvy-status--ok" };
}

// Helper: Extract CN from a distinguished name string
function extractCN(distinguishedName) {
  if (!distinguishedName || typeof distinguishedName !== "string") return "Unknown";
  var match = distinguishedName.match(/CN=([^\/]+)/);
  return match ? match[1].trim() : distinguishedName;
}

// Helper: Format Subject Alternative Names
function formatSANs(sanArray) {
  if (!sanArray || !Array.isArray(sanArray.array) || sanArray.array.length === 0) {
    return '<span class="uvy-unknown">N/A</span>';
  }

  try {
    let sanList = '<ul class="san-list">';

    for (let i = 0; i < sanArray.array.length; i++) {
      const san = sanArray.array[i];
      if (san.dns) {
        sanList += `<li><span class="uvy-badge">DNS</span><span class="domain-container">${escapeHtml(san.dns)}</span></li>`;
      } else if (san.ip) {
        sanList += `<li><span class="uvy-badge">IP</span><span class="domain-container">${escapeHtml(san.ip)}</span></li>`;
      } else if (san.email) {
        sanList += `<li><span class="uvy-badge">Email</span><span class="domain-container">${escapeHtml(san.email)}</span></li>`;
      } else if (san.uri) {
        sanList += `<li><span class="uvy-badge">URI</span><span class="domain-container">${escapeHtml(san.uri)}</span></li>`;
      } else {
        sanList += `<li><span class="domain-container">${escapeHtml(JSON.stringify(san))}</span></li>`;
      }
    }

    sanList += "</ul>";
    return sanList;
  } catch (e) {
    console.error("Error formatting SANs:", e);
    return '<span class="uvy-unknown">Error formatting SANs</span>';
  }
}

// Helper: Format Extended Key Usage
function formatExtendedKeyUsage(ekuExt) {
  if (!ekuExt || !Array.isArray(ekuExt.array) || ekuExt.array.length === 0) {
    return '<span class="uvy-unknown">N/A</span>';
  }

  const ekuLabels = {
    "serverAuth": "Server Authentication",
    "clientAuth": "Client Authentication",
    "codeSigning": "Code Signing",
    "emailProtection": "Email Protection",
    "timeStamping": "Time Stamping",
    "OCSP Signing": "OCSP Signing",
    "smartcardLogon": "Smartcard Logon",
    "serverGatedCrypto": "Server-Gated Crypto"
  };

  const items = ekuExt.array.map((usage) => {
    const label = ekuLabels[usage] || usage;
    return `<span class="uvy-badge">${escapeHtml(label)}</span>`;
  });

  return `<div class="eku-list">${items.join("")}</div>`;
}

// Helper: Format hex string with colons for better readability
function formatHexWithColons(hexString) {
  if (!hexString) return "Unknown";
  return hexString.replace(/(.{2})(?!$)/g, "$1:").toLowerCase();
}

// Helper: Format distinguished name string into readable HTML
function formatDistinguishedName(dnString) {
  if (!dnString || typeof dnString !== "string") return "Unknown";

  const parts = dnString.split("/").filter((p) => p.length > 0);
  const labels = {
    "C": "Country",
    "ST": "State/Province",
    "L": "Locality",
    "O": "Organization",
    "OU": "Organizational Unit",
    "CN": "Common Name",
    "E": "Email",
    "DC": "Domain Component"
  };

  let formattedDN = '<div class="dn-container">';
  parts.forEach((part) => {
    const sepIdx = part.indexOf("=");
    if (sepIdx > 0) {
      const key = part.slice(0, sepIdx);
      const value = part.slice(sepIdx + 1);
      if (key && value) {
        const displayLabel = labels[key] ? `${labels[key]} (${key})` : key;
        formattedDN += `<div class="dn-item"><span class="dn-label">${escapeHtml(displayLabel)}</span><span class="dn-value">${escapeHtml(value)}</span></div>`;
      }
    }
  });
  formattedDN += "</div>";

  return formattedDN;
}

// Helper: Build a compact copy button
function renderCopyButton(text, ariaLabel) {
  return `<button type="button" class="uvy-button--quiet uvy-button--small uvy-copy" data-cert-copy="${escapeHtml(text)}" aria-label="${escapeHtml(ariaLabel)}"><span data-copy class="with-icon">${tablerIcon("tabler-copy", "icon-small")}Copy</span><span data-copied class="with-icon">${tablerIcon("tabler-check", "icon-small")}Copied</span></button>`;
}

// Helper: Copy text with clipboard API + fallback
async function copyTextToClipboard(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const area = document.createElement("textarea");
  area.value = text;
  area.setAttribute("readonly", "");
  area.style.position = "fixed";
  area.style.opacity = "0";
  document.body.append(area);
  area.select();
  document.execCommand("copy");
  area.remove();
}

// Helper: Update certificate status pill in the details header
function setCertificateStatus(status) {
  const statusEl = document.getElementById("cert-status");
  if (!statusEl) return;
  if (!status) {
    statusEl.hidden = true;
    statusEl.className = "";
    statusEl.textContent = "";
    return;
  }
  statusEl.className = status.className;
  statusEl.textContent = status.label;
  statusEl.hidden = false;
}

// Helper: Render empty state in #output
function renderEmptyState() {
  const output = document.getElementById("output");
  const input = document.getElementById("cert-input");
  if (input) input.removeAttribute("aria-invalid");
  setCertificateStatus(null);
  output.innerHTML = `
    <div class="uvy-empty">
      <div class="cert-empty-icon">${tablerIcon("tabler-file-text", "icon-large icon-muted")}</div>
      <strong>No certificate processed yet</strong>
      <p>Paste a PEM-formatted certificate on the left to inspect its subject, issuer, validity window, fingerprints and domains.</p>
    </div>
  `;
}

// Helper: Render error alert in #output
function renderErrorState(title, message) {
  const output = document.getElementById("output");
  const input = document.getElementById("cert-input");
  if (input) input.setAttribute("aria-invalid", "true");
  setCertificateStatus({ label: "Invalid PEM", className: "uvy-status uvy-status--danger" });
  output.innerHTML = `
    <div class="uvy-alert uvy-alert--danger" role="alert">
      ${tablerIcon("tabler-alert-circle")}
      <div><strong>${escapeHtml(title)}:</strong> ${escapeHtml(message)}</div>
    </div>
  `;
}

// Helper: Show/hide the clear button
function updateClearButton(hasText) {
  const clearBtn = document.getElementById("clear-cert-btn");
  if (clearBtn) {
    clearBtn.hidden = !hasText;
  }
}

// Helper: Show the copy link button
function showCopyLinkButton() {
  const container = document.getElementById("copy-link-container");
  if (container) container.hidden = false;
}

// Helper: Hide the copy link button
function hideCopyLinkButton() {
  const container = document.getElementById("copy-link-container");
  const success = document.getElementById("copy-success");
  const btn = document.getElementById("copy-link-btn");
  if (container) container.hidden = true;
  if (success) success.hidden = true;
  if (btn) btn.classList.remove("is-copied");
}

// Helper: Encode certificate for URL sharing
function encodeCertificateForURL(certText) {
  try {
    return btoa(encodeURIComponent(certText));
  } catch (e) {
    console.error("Error encoding certificate for URL:", e);
    return null;
  }
}

// Helper: Decode certificate from URL
function decodeCertificateFromURL(encodedCert) {
  try {
    return decodeURIComponent(atob(encodedCert));
  } catch (e) {
    console.error("Error decoding certificate from URL:", e);
    return null;
  }
}

// Helper: Copy shareable link to clipboard
function copyShareableLink() {
  var certText = document.getElementById("cert-input").value.trim();
  if (!certText || certText.indexOf("-----BEGIN CERTIFICATE-----") === -1) {
    return;
  }

  var encodedCert = encodeCertificateForURL(certText);
  if (!encodedCert) {
    alert("Error creating shareable link");
    return;
  }

  var shareableURL = window.location.origin + window.location.pathname + "#" + encodedCert;
  var copyBtn = document.getElementById("copy-link-btn");
  var successSpan = document.getElementById("copy-success");

  copyTextToClipboard(shareableURL).then(function () {
    if (copyBtn) copyBtn.classList.add("is-copied");
    if (successSpan) successSpan.hidden = false;

    clearTimeout(copyShareableLink._timer);
    copyShareableLink._timer = setTimeout(function () {
      if (copyBtn) copyBtn.classList.remove("is-copied");
      if (successSpan) successSpan.hidden = true;
    }, 3000);
  }).catch(function (err) {
    console.error("Failed to copy to clipboard:", err);
    alert("Copy this link to share:\n\n" + shareableURL);
  });
}

// Helper: Load certificate from URL hash
function loadCertificateFromURL() {
  var hash = window.location.hash;
  if (hash && hash.length > 1) {
    var encodedCert = hash.substring(1); // Remove the # character
    var certText = decodeCertificateFromURL(encodedCert);

    if (certText && certText.indexOf("-----BEGIN CERTIFICATE-----") !== -1) {
      var input = document.getElementById("cert-input");
      input.value = certText;
      input.scrollTop = 0;
      updateClearButton(true);
      if (processCertificate(certText)) {
        showCopyLinkButton();
      } else {
        hideCopyLinkButton();
      }
    }
  }
}

function processCertificate(pem) {
  var output = document.getElementById("output");
  var input = document.getElementById("cert-input");

  if (pem.indexOf("-----BEGIN CERTIFICATE-----") === -1) {
    renderErrorState(
      "Invalid certificate format",
      "Paste a PEM-encoded X.509 certificate starting with -----BEGIN CERTIFICATE-----."
    );
    return false;
  }

  try {
    var x509 = new X509();
    x509.readCertPEM(pem);

    // Identity Information
    var subjectStr = x509.getSubjectString();
    var primaryCN = extractCN(subjectStr);
    var sanExt = x509.getExtSubjectAltName();
    var formattedSANs = formatSANs(sanExt);
    var ekuExt = x509.getExtExtKeyUsage();
    var formattedEKU = formatExtendedKeyUsage(ekuExt);

    // Certificate Validation
    var issuerStr = x509.getIssuerString();
    var notBefore = x509.getNotBefore();
    var notAfter = x509.getNotAfter();

    var notBeforeDate = parseCertDate(notBefore);
    var notAfterDate = parseCertDate(notAfter);
    var certLifetime = Math.round((notAfterDate - notBeforeDate) / (1000 * 60 * 60 * 24));

    var formattedNotBefore = formatDate(notBefore);
    var formattedNotAfter = formatDate(notAfter);
    var validityStatus = getValidityStatus(notBeforeDate, notAfterDate);

    // Format the distinguished name strings
    var formattedIssuer = formatDistinguishedName(issuerStr);
    var formattedSubject = formatDistinguishedName(subjectStr);

    // Get and format serial number
    var serialNumberHex = x509.getSerialNumberHex().toUpperCase();
    var formattedSerialNumber = formatHexWithColons(serialNumberHex);

    // Fingerprints
    var certHex = x509.hex;
    var sha1Fingerprint = KJUR.crypto.Util.hashHex(certHex, "sha1").toUpperCase();
    var formattedSha1Fingerprint = formatHexWithColons(sha1Fingerprint);
    var sha256Fingerprint = KJUR.crypto.Util.hashHex(certHex, "sha256").toUpperCase();
    var formattedSha256Fingerprint = formatHexWithColons(sha256Fingerprint);

    var sha1Link = `<a class="cert-ext-link" href="https://crt.sh/?q=${encodeURIComponent(sha1Fingerprint)}" target="_blank" rel="noopener noreferrer">crt.sh${tablerIcon("tabler-external-link", "icon-small")}</a>`;
    var sha256Link = `<a class="cert-ext-link" href="https://crt.sh/?q=${encodeURIComponent(sha256Fingerprint)}" target="_blank" rel="noopener noreferrer">crt.sh${tablerIcon("tabler-external-link", "icon-small")}</a>`;

    // Security & Cryptographic Info
    var pubKey = x509.getPublicKey();
    var keyAlgorithm = pubKey.type ? pubKey.type : "Unknown";
    var signatureAlgorithm = x509.getSignatureAlgorithmField();

    // Certificate Version
    var certVersion = x509.getVersion() + 1;

    // Public Key Size
    var keySize = "N/A";
    if (pubKey.type === "RSA" && pubKey.n) {
      keySize = pubKey.n.bitLength() + " bits";
    } else if (pubKey.type === "EC" && pubKey.curveName) {
      keySize = pubKey.curveName;
    } else if (pubKey.type === "DSA" && pubKey.p) {
      keySize = pubKey.p.bitLength() + " bits";
    }

    if (input) input.removeAttribute("aria-invalid");
    setCertificateStatus(validityStatus);

    var html = `
      <div class="uvy-output cert-output-cn">
        <span class="cert-output-cn__value"><span class="uvy-output__prompt" aria-hidden="true">&gt;</span><span>${escapeHtml(primaryCN)}</span></span>
        ${renderCopyButton(primaryCN, "Copy primary domain")}
      </div>
      <dl class="uvy-kv cert-kv">
        <div>
          <dt>Subject</dt>
          <dd>
            ${formattedSubject}
            <code class="raw-dn">${escapeHtml(subjectStr)}</code>
          </dd>
        </div>
        <div>
          <dt>Issuer</dt>
          <dd>
            ${formattedIssuer}
            <code class="raw-dn">${escapeHtml(issuerStr)}</code>
          </dd>
        </div>
        <div>
          <dt>Serial number</dt>
          <dd class="cert-hex-block">
            <code class="cert-hex-value">${escapeHtml(formattedSerialNumber)}</code>
            <div class="cert-hex-meta">
              <code class="raw-dn cert-hex-raw">${escapeHtml(serialNumberHex)}</code>
              <span class="cert-inline-actions">
                ${renderCopyButton(serialNumberHex, "Copy serial number")}
              </span>
            </div>
          </dd>
        </div>
        <div>
          <dt>Version</dt>
          <dd><span class="uvy-badge">V${escapeHtml(certVersion)}</span></dd>
        </div>
        <div>
          <dt>Valid from</dt>
          <dd><time datetime="${notBeforeDate ? notBeforeDate.toISOString() : ""}">${escapeHtml(formattedNotBefore)}</time></dd>
        </div>
        <div>
          <dt>Valid to</dt>
          <dd><time datetime="${notAfterDate ? notAfterDate.toISOString() : ""}">${escapeHtml(formattedNotAfter)}</time></dd>
        </div>
        <div>
          <dt>Validity period</dt>
          <dd><span class="uvy-mono">${escapeHtml(certLifetime)} days</span></dd>
        </div>
        <div>
          <dt>SHA-1 fingerprint</dt>
          <dd class="cert-hex-block">
            <code class="cert-hex-value">${escapeHtml(formattedSha1Fingerprint)}</code>
            <div class="cert-hex-meta">
              <code class="raw-dn cert-hex-raw">${escapeHtml(sha1Fingerprint)}</code>
              <span class="cert-inline-actions">
                ${renderCopyButton(sha1Fingerprint, "Copy SHA-1 fingerprint")}
                ${sha1Link}
              </span>
            </div>
          </dd>
        </div>
        <div>
          <dt>SHA-256 fingerprint</dt>
          <dd class="cert-hex-block">
            <code class="cert-hex-value">${escapeHtml(formattedSha256Fingerprint)}</code>
            <div class="cert-hex-meta">
              <code class="raw-dn cert-hex-raw">${escapeHtml(sha256Fingerprint)}</code>
              <span class="cert-inline-actions">
                ${renderCopyButton(sha256Fingerprint, "Copy SHA-256 fingerprint")}
                ${sha256Link}
              </span>
            </div>
          </dd>
        </div>
        <div>
          <dt>Extended key usage</dt>
          <dd>${formattedEKU}</dd>
        </div>
        <div>
          <dt>Key algorithm</dt>
          <dd><span class="uvy-badge">${escapeHtml(keyAlgorithm)}</span></dd>
        </div>
        <div>
          <dt>Key size</dt>
          <dd><span class="uvy-badge">${escapeHtml(keySize)}</span></dd>
        </div>
        <div>
          <dt>Signature algorithm</dt>
          <dd><span class="uvy-badge">${escapeHtml(signatureAlgorithm)}</span></dd>
        </div>
        <div>
          <dt>Primary domain (CN)</dt>
          <dd><span class="domain-container">${escapeHtml(primaryCN)}</span></dd>
        </div>
        <div>
          <dt>Additional domains (SANs)</dt>
          <dd>${formattedSANs}</dd>
        </div>
      </dl>
    `;
    output.innerHTML = html;
    return true;
  } catch (e) {
    renderErrorState(
      "Error decoding certificate",
      "Check that the PEM certificate block is complete and unmodified, then try again."
    );
    return false;
  }
}

document.addEventListener("DOMContentLoaded", function () {
  var certInput = document.getElementById("cert-input");
  var copyLinkBtn = document.getElementById("copy-link-btn");
  var clearCertBtn = document.getElementById("clear-cert-btn");
  var output = document.getElementById("output");

  // Load certificate from URL hash on page load
  loadCertificateFromURL();

  // Process certificate when text input changes
  if (certInput) {
    certInput.addEventListener("input", function () {
      var certText = this.value.trim();
      updateClearButton(certText.length > 0);
      if (!certText) {
        renderEmptyState();
        hideCopyLinkButton();
        return;
      }
      if (processCertificate(certText)) {
        showCopyLinkButton();
      } else {
        hideCopyLinkButton();
      }
    });
  }

  // Clear button resets input and output
  if (clearCertBtn) {
    clearCertBtn.addEventListener("click", function () {
      if (certInput) {
        certInput.value = "";
        certInput.focus();
      }
      updateClearButton(false);
      hideCopyLinkButton();
      renderEmptyState();
      if (window.location.hash) {
        history.replaceState(null, "", window.location.pathname + window.location.search);
      }
    });
  }

  // Copy shareable link functionality
  if (copyLinkBtn) {
    copyLinkBtn.addEventListener("click", function () {
      copyShareableLink();
    });
  }

  // Event delegation for dynamically rendered copy buttons inside #output
  if (output) {
    output.addEventListener("click", function (event) {
      var button = event.target.closest("[data-cert-copy]");
      if (!button) return;
      var text = button.getAttribute("data-cert-copy");
      if (!text) return;
      copyTextToClipboard(text).then(function () {
        button.classList.add("is-copied");
        clearTimeout(button._copyTimer);
        button._copyTimer = setTimeout(function () {
          button.classList.remove("is-copied");
        }, 1800);
      }).catch(function () {});
    });
  }
});
