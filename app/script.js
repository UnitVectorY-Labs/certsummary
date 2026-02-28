// Helper: Parse certificate date components from string
function parseCertDateComponents(certDateStr) {
  if (!certDateStr || certDateStr.length < 13) return null;
  
  let year, month, day, hour, minute, second;
  
  // Check if it's UTCTime format (YYMMDDhhmmssZ)
  if (certDateStr.length === 13 && certDateStr.endsWith('Z')) {
    const yearPrefix = parseInt(certDateStr.substring(0, 2), 10) >= 50 ? '19' : '20';
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
  
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 
                  'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  
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

// Helper: Extract CN from a distinguished name string
function extractCN(distinguishedName) {
  if (!distinguishedName || typeof distinguishedName !== 'string') return "Unknown";
  var match = distinguishedName.match(/CN=([^\/]+)/);
  return match ? match[1].trim() : distinguishedName;
}

// Helper: Format Subject Alternative Names as pills
function formatSANs(sanArray) {
  if (!sanArray || !Array.isArray(sanArray.array)) return "N/A";
  
  try {
    let sanList = '<div class="san-wrap"><div class="san-list">';
    
    for (let i = 0; i < sanArray.array.length; i++) {
      const san = sanArray.array[i];
      if (san.dns) {
        sanList += `<span class="san-pill">DNS: ${san.dns}</span>`;
      } else if (san.ip) {
        sanList += `<span class="san-pill">IP: ${san.ip}</span>`;
      } else if (san.email) {
        sanList += `<span class="san-pill">Email: ${san.email}</span>`;
      } else if (san.uri) {
        sanList += `<span class="san-pill">URI: ${san.uri}</span>`;
      } else {
        sanList += `<span class="san-pill">${JSON.stringify(san)}</span>`;
      }
    }
    
    sanList += '</div></div>';
    return sanList;
  } catch (e) {
    console.error("Error formatting SANs:", e);
    return "Error formatting SANs";
  }
}

// Helper: Format hex string with colons for better readability
function formatHexWithColons(hexString) {
  if (!hexString) return "Unknown";
  // Insert a colon after every 2 characters (except the last pair)
  return hexString.replace(/(.{2})(?!$)/g, '$1:').toLowerCase();
}

// Helper: Format distinguished name string into readable HTML
function formatDistinguishedName(dnString) {
  if (!dnString || typeof dnString !== 'string') return "Unknown";
  
  // Parse the DN string which is typically in the format: /C=US/ST=State/L=Locality/O=Org/CN=Name
  const parts = dnString.split('/').filter(p => p.length > 0);
  const labels = {
    'C': 'Country',
    'ST': 'State/Province',
    'L': 'Locality',
    'O': 'Organization',
    'OU': 'Organizational Unit',
    'CN': 'Common Name',
    'E': 'Email',
    'DC': 'Domain Component'
  };
  
  let formattedDN = '<div class="dn-container">';
  parts.forEach(part => {
    const [key, value] = part.split('=');
    if (key && value) {
      const label = labels[key] || key;
      // If the key isn't in our known labels, just show the original key with the friendly name in parentheses
      // If it is a known key, show the friendly name with the original key in parentheses
      const displayLabel = labels[key] ? `${labels[key]} (${key})` : key;
      formattedDN += `<div class="dn-item"><span class="dn-label">${displayLabel}:</span> ${value}</div>`;
    }
  });
  formattedDN += '</div>';
  
  return formattedDN;
}

// Helper: Show the copy link button
function showCopyLinkButton() {
  document.getElementById('copy-link-container').style.display = 'block';
}

// Helper: Hide the copy link button
function hideCopyLinkButton() {
  document.getElementById('copy-link-container').style.display = 'none';
  document.getElementById('copy-success').style.display = 'none';
}

// Helper: Encode certificate for URL sharing
function encodeCertificateForURL(certText) {
  try {
    return btoa(encodeURIComponent(certText));
  } catch (e) {
    console.error('Error encoding certificate for URL:', e);
    return null;
  }
}

// Helper: Decode certificate from URL
function decodeCertificateFromURL(encodedCert) {
  try {
    return decodeURIComponent(atob(encodedCert));
  } catch (e) {
    console.error('Error decoding certificate from URL:', e);
    return null;
  }
}

// Helper: Copy shareable link to clipboard
function copyShareableLink() {
  var certText = document.getElementById('cert-input').value.trim();
  if (!certText || certText.indexOf('-----BEGIN CERTIFICATE-----') === -1) {
    return;
  }

  var encodedCert = encodeCertificateForURL(certText);
  if (!encodedCert) {
    alert('Error creating shareable link');
    return;
  }

  var shareableURL = window.location.origin + window.location.pathname + '#' + encodedCert;
  
  // Copy to clipboard
  navigator.clipboard.writeText(shareableURL).then(function() {
    // Show success message
    var successSpan = document.getElementById('copy-success');
    successSpan.style.display = 'inline';
    
    // Hide success message after 3 seconds
    setTimeout(function() {
      successSpan.style.display = 'none';
    }, 3000);
  }).catch(function(err) {
    console.error('Failed to copy to clipboard:', err);
    // Fallback: show the URL in an alert
    alert('Copy this link to share:\n\n' + shareableURL);
  });
}

// Helper: Copy PEM from pre block
function copyPEM(button) {
  var preBlock = button.parentElement.querySelector('.pem-block');
  if (!preBlock) return;
  
  navigator.clipboard.writeText(preBlock.textContent).then(function() {
    var originalText = button.innerHTML;
    button.textContent = '✓ Copied!';
    setTimeout(function() {
      button.innerHTML = originalText;
    }, 2000);
  }).catch(function(err) {
    console.error('Failed to copy PEM:', err);
  });
}

// Helper: Load certificate from URL hash
function loadCertificateFromURL() {
  var hash = window.location.hash;
  if (hash && hash.length > 1) {
    var encodedCert = hash.substring(1); // Remove the # character
    var certText = decodeCertificateFromURL(encodedCert);
    
    if (certText && certText.indexOf('-----BEGIN CERTIFICATE-----') !== -1) {
      document.getElementById('cert-input').value = certText;
      processCertificate(certText);
      showCopyLinkButton();
    }
  }
}

function processCertificate(pem) {
  var output = document.getElementById('output');
  if (pem.indexOf('-----BEGIN CERTIFICATE-----') === -1) {
    output.innerHTML = '<div class="error-card"><p>Invalid certificate format.</p></div>';
    return;
  }
  try {
    var x509 = new X509();
    x509.readCertPEM(pem);

    // Identity Information
    var subjectStr = x509.getSubjectString(); // e.g., "/C=US/ST=California/CN=example.com"
    var primaryCN = extractCN(subjectStr);
    var sanExt = x509.getExtSubjectAltName(); // Returns array of objects with SANs
    var formattedSANs = formatSANs(sanExt);
    var sanCount = (sanExt && Array.isArray(sanExt.array)) ? sanExt.array.length : 0;

    // Certificate Validation
    var issuerStr = x509.getIssuerString();
    var notBefore = x509.getNotBefore();
    var notAfter = x509.getNotAfter();
    console.log(notBefore, notAfter);
    
    // Parse dates to Date objects before calculating the difference
    var notBeforeDate = parseCertDate(notBefore);
    var notAfterDate = parseCertDate(notAfter);
    
    // Calculate lifetime in days
    var certLifetime = Math.round((notAfterDate - notBeforeDate) / (1000 * 60 * 60 * 24)); // Days
    
    var formattedNotBefore = formatDate(notBefore);
    var formattedNotAfter = formatDate(notAfter);

    // Check if expired or not yet valid
    var now = new Date();
    var isExpired = notAfterDate < now;
    var isNotYetValid = notBeforeDate > now;
    
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
    var sha1Link = `<a class="detail-link" href="https://crt.sh/?q=${sha1Fingerprint}" target="_blank">↗️ crt.sh</a>`;
    var sha256Link = `<a class="detail-link" href="https://crt.sh/?q=${sha256Fingerprint}" target="_blank">↗️ crt.sh</a>`;

    // Security & Cryptographic Info
    var pubKey = x509.getPublicKey();
    var keyAlgorithm = pubKey.type ? pubKey.type : "Unknown";
    var signatureAlgorithm = x509.getSignatureAlgorithmField();
    
    // Certificate Version (1-indexed as per X.509 convention: 1, 2, or 3)
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

    // Validity status classes
    var notBeforeClass = isNotYetValid ? 'detail-expired' : 'detail-valid';
    var notAfterClass = isExpired ? 'detail-expired' : 'detail-valid';

    // Build the cert-observatory style card layout
    var html = `
      <div class="cert-card">
        <div class="cert-top">
          <span class="cert-label">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M12 15a3 3 0 1 0 6 0a3 3 0 1 0 -6 0" /><path d="M13 17.5v4.5l2 -1.5l2 1.5v-4.5" /><path d="M10 19h-5a2 2 0 0 1 -2 -2v-10c0 -1.1 .9 -2 2 -2h14a2 2 0 0 1 2 2v10a2 2 0 0 1 -1 1.73" /><path d="M6 9l12 0" /><path d="M6 12l3 0" /><path d="M6 15l2 0" /></svg>
            Certificate — ${primaryCN}
          </span>
        </div>
        <div class="cert-content">
          <div class="pem-column">
            <div class="pem-wrap">
              <pre class="pem-block">${pem}</pre>
              <button type="button" class="btn-copy" onclick="copyPEM(this)">
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M7 9.667a2.667 2.667 0 0 1 2.667 -2.667h8.666a2.667 2.667 0 0 1 2.667 2.667v8.666a2.667 2.667 0 0 1 -2.667 2.667h-8.666a2.667 2.667 0 0 1 -2.667 -2.667l0 -8.666" /><path d="M4.012 16.737a2.005 2.005 0 0 1 -1.012 -1.737v-10c0 -1.1 .9 -2 2 -2h10c.75 0 1.158 .385 1.5 1" /></svg>
                Copy PEM
              </button>
            </div>
          </div>
          <div class="details-stack">
            <div class="detail-grid">
              <div class="detail-item">
                <div class="detail-label">Subject</div>
                <div class="detail-box">
                  ${formattedSubject}
                  <small class="raw-dn">${subjectStr}</small>
                </div>
              </div>
              <div class="detail-item">
                <div class="detail-label">Issuer</div>
                <div class="detail-box">
                  ${formattedIssuer}
                  <small class="raw-dn">${issuerStr}</small>
                </div>
              </div>
            </div>
            <div class="detail-grid">
              <div class="detail-item">
                <div class="detail-label">Not Before</div>
                <div class="detail-value ${notBeforeClass}">${formattedNotBefore}</div>
              </div>
              <div class="detail-item">
                <div class="detail-label">Not After</div>
                <div class="detail-value ${notAfterClass}">${formattedNotAfter}</div>
              </div>
            </div>
            <div class="detail-grid">
              <div class="detail-item">
                <div class="detail-label">Validity Period</div>
                <div class="detail-value detail-muted">${certLifetime} days</div>
              </div>
              <div class="detail-item">
                <div class="detail-label">Version</div>
                <div class="detail-value detail-muted">V${certVersion}</div>
              </div>
            </div>
            <div class="detail-grid">
              <div class="detail-item">
                <div class="detail-label">Serial Number</div>
                <div class="detail-box detail-box-mono">
                  ${formattedSerialNumber}
                  <small class="raw-dn">${serialNumberHex}</small>
                </div>
              </div>
              <div class="detail-item">
                <div class="detail-label">Signature Algorithm</div>
                <div class="detail-box">${signatureAlgorithm}</div>
              </div>
            </div>
            <div class="detail-grid">
              <div class="detail-item">
                <div class="detail-label">Public Key</div>
                <div class="detail-box">${keyAlgorithm}</div>
              </div>
              <div class="detail-item">
                <div class="detail-label">Key Size</div>
                <div class="detail-box">${keySize}</div>
              </div>
            </div>
            <div class="detail-item">
              <div class="detail-label">SHA-256 Fingerprint</div>
              <div class="detail-box detail-box-mono">
                ${formattedSha256Fingerprint}
                <small class="raw-dn">${sha256Fingerprint}</small>
                ${sha256Link}
              </div>
            </div>
            <div class="detail-item">
              <div class="detail-label">SHA-1 Fingerprint</div>
              <div class="detail-box detail-box-mono">
                ${formattedSha1Fingerprint}
                <small class="raw-dn">${sha1Fingerprint}</small>
                ${sha1Link}
              </div>
            </div>
            <div class="detail-item">
              <div class="detail-label">Primary Domain (CN)</div>
              <div class="detail-box detail-box-mono">${primaryCN}</div>
            </div>
            <div class="detail-item">
              <div class="detail-label">Subject Alternative Names (${sanCount})</div>
              ${formattedSANs}
            </div>
          </div>
        </div>
      </div>
    `;
    output.innerHTML = html;
  } catch (e) {
    output.innerHTML = '<div class="error-card"><p>Error decoding certificate.</p></div>';
  }
}