// Helper: Format certificate dates to standard format (MMM DD HH:MM:SS YYYY GMT)
function formatDate(certDateStr) {
  // Handle both UTCTime (YYMMDDhhmmssZ) and GeneralizedTime (YYYYMMDDhhmmssZ) formats
  if (!certDateStr || certDateStr.length < 13) return certDateStr;
  
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 
                  'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  
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
  
  return `${months[month]} ${parseInt(day, 10)} ${hour}:${minute}:${second} ${year} GMT`;
}

// Helper: Extract CN from a distinguished name string
function extractCN(distinguishedName) {
  if (!distinguishedName || typeof distinguishedName !== 'string') return "Unknown";
  var match = distinguishedName.match(/CN=([^\/]+)/);
  return match ? match[1].trim() : distinguishedName;
}

// Helper: Format Subject Alternative Names
function formatSANs(sanArray) {
  if (!sanArray || !Array.isArray(sanArray.array)) return "N/A";
  
  try {
    // Create an unordered list for the SANs
    let sanList = "<ul style='margin: 0; padding-left: 20px;'>";
    
    // Loop through the SANs and add each as a list item
    for (let i = 0; i < sanArray.array.length; i++) {
      const san = sanArray.array[i];
      if (san.dns) {
        sanList += `<li>DNS: <span class="domain-container">${san.dns}</span></li>`;
      } else if (san.ip) {
        sanList += `<li>IP: <span class="domain-container">${san.ip}</span></li>`;
      } else if (san.email) {
        sanList += `<li>Email: <span class="domain-container">${san.email}</span></li>`;
      } else if (san.uri) {
        sanList += `<li>URI: <span class="domain-container">${san.uri}</span></li>`;
      } else {
        sanList += `<li>${JSON.stringify(san)}</li>`;
      }
    }
    
    sanList += "</ul>";
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

function processCertificate(pem) {
  var output = document.getElementById('output');
  if (pem.indexOf('-----BEGIN CERTIFICATE-----') === -1) {
    output.innerHTML = '<p style="color:red;">Invalid certificate format.</p>';
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

    // Certificate Validation
    var issuerStr = x509.getIssuerString();
    var notBefore = x509.getNotBefore();
    var notAfter = x509.getNotAfter();
    var formattedNotBefore = formatDate(notBefore);
    var formattedNotAfter = formatDate(notAfter);
    
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
    var sha1Link = `<a href="https://crt.sh/?q=${sha1Fingerprint}" target="_blank">↗️ crt.sh</a>`;
    var sha256Link = `<a href="https://crt.sh/?q=${sha256Fingerprint}" target="_blank">↗️ crt.sh</a>`;

    // Security & Cryptographic Info
    var pubKey = x509.getPublicKey();
    var keyAlgorithm = pubKey.type ? pubKey.type : "Unknown";
    var signatureAlgorithm = x509.getSignatureAlgorithmField();

    // Build the details table (alternating row colors applied via CSS)
    var html = `
      <table>
        <tr>
          <td>Subject</td>
          <td>
            ${formattedSubject}
            <small class="raw-dn">${subjectStr}</small>
          </td>
        </tr>
        <tr>
          <td>Issuer</td>
          <td>
            ${formattedIssuer}
            <small class="raw-dn">${issuerStr}</small>
          </td>
        </tr>
        <tr>
          <td>Serial Number</td>
          <td>
            <div class="scroll-container">${formattedSerialNumber}</div>
            <small class="scroll-container raw-dn">${serialNumberHex}</small>
            </td>
        </tr>
        <tr>
          <td>Valid From</td>
          <td>${formattedNotBefore}</td>
        </tr>
        <tr>
          <td>Valid To</td>
          <td>${formattedNotAfter}</td>
        </tr>
        <tr>
          <td>SHA-1 Fingerprint</td>
          <td>
           <div class="scroll-container">${formattedSha1Fingerprint}</div>
           <small class="scroll-container raw-dn">${sha1Fingerprint}</small>
           ${sha1Link}
           </td>
        </tr>
        <tr>
          <td>SHA-256 Fingerprint</td>
          <td>
            <div class="scroll-container">${formattedSha256Fingerprint}</div>
            <small class="scroll-container raw-dn">${sha256Fingerprint}</small>
            ${sha256Link}
          </td>
        </tr>
        <tr>
          <td>Key Algorithm</td>
          <td>${keyAlgorithm}</td>
        </tr>
        <tr>
          <td>Signature Algorithm</td>
          <td>${signatureAlgorithm}</td>
        </tr>
        <tr>
          <td>Primary Domain (CN)</td>
          <td><span class="domain-container">${primaryCN}</span></td>
        </tr>
        <tr>
          <td>Additional Domains (SANs)</td>
          <td>${formattedSANs}</td>
        </tr>
      </table>
    `;
    output.innerHTML = html;
  } catch (e) {
    output.innerHTML = '<p style="color:red;">Error decoding certificate.</p>';
  }
}