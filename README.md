[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT) [![Active](https://img.shields.io/badge/Status-Active-green)](https://guide.unitvectorylabs.com/bestpractices/status/#active)

# certsummary

A tool for securely decoding and inspecting SSL/TLS certificates directly in your web browser.

## Overview

**certsummary** lets you decode and inspect SSL/TLS certificates right in your browser—no server interaction required. Simply visit [https://certsummary.unitvectorylabs.com/](https://certsummary.unitvectorylabs.com/), paste in a PEM-formatted certificate, and see all the key details instantly. Built with vanilla JavaScript and HTML, it leverages the [jsrsasign](https://github.com/kjur/jsrsasign) library for reliable certificate parsing and decoding.

## Features
- Decode and inspect PEM-formatted SSL/TLS certificates
- Extract and display essential certificate details
- Compute and display SHA-1 and SHA-256 fingerprints
- Provide clickable links to [crt.sh](https://crt.sh) for extended analysis
