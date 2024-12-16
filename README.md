
# XSS-Scanner

![XSS-Scanner Banner](https://via.placeholder.com/800x200?text=XSS-Scanner+by+Karthik+S+Sathyan)

---

## Table of Contents
- [Introduction](#introduction)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Scan a Single URL](#scan-a-single-url)
  - [Scan from a File](#scan-from-a-file)
  - [Collect URLs from Wayback Machine](#collect-urls-from-wayback-machine)
- [Payloads](#payloads)
- [Screenshots](#screenshots)
- [Disclaimer](#disclaimer)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

---

## Introduction
The **XSS-Scanner** is a powerful tool designed to detect **Cross-Site Scripting (XSS)** vulnerabilities in web applications. Built with Python, it automates the process of identifying vulnerable endpoints, testing payloads, and reporting potential vulnerabilities. This tool helps ethical hackers and security researchers secure applications against malicious XSS attacks.

---

## Features
- 🚀 **Fast and Reliable Scanning**: Supports GET and POST methods.
- 📄 **Form Scraping**: Automatically extracts and tests form fields.
- 🛠️ **Payload Testing**: Runs a comprehensive set of XSS payloads to identify vulnerabilities.
- 🌐 **Wayback Machine Integration**: Collects historical URLs for scanning.
- 🔍 **URL Filtering**: Filters potential XSS-prone URLs based on common parameters.
- 📂 **Batch Processing**: Scans multiple URLs from a file.
- 🎨 **Interactive ASCII Banner**: Adds a touch of style to your terminal interface.

---

## Requirements
- Python 3.8+
- Required Python libraries:
  - `requests`
  - `beautifulsoup4`
  - `urllib3`

---

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/Karthikdude/XSS-Scanner
   cd XSS-Scanner
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Add the `waybackurls` tool (optional for Wayback Machine integration):
   ```bash
   go install github.com/tomnomnom/waybackurls@latest
   ```

---

## Usage

### Scan a Single URL
```bash
python xss_scanner.py
```
1. Select the **Single URL** scan option.
2. Enter the URL to scan.

### Scan from a File
1. Prepare a `.txt` file containing URLs (one per line).
2. Run the script and select the **File Scan** option:
   ```bash
   python xss_scanner.py
   ```
3. Provide the path to your `.txt` file.

### Collect URLs from Wayback Machine
1. Select the **Wayback Machine** scan option.
2. Enter a domain name (e.g., `example.com`).
3. The tool will collect URLs and scan for vulnerabilities.

---

## Payloads
The scanner uses a list of XSS payloads stored in `xsspayloads.txt`. You can customize the payloads file to include additional test cases. Example payloads:
```html
<script>alert('XSS')</script>
"/><img src=x onerror=alert(1)>
```

## Disclaimer
This tool is intended for **educational purposes** and **authorized testing only**. Use it responsibly and ensure you have proper permissions before testing any web application. **Misuse** of this tool can lead to **legal consequences**.

---

## Contributing
Contributions are welcome! Feel free to fork the repository, create issues, or submit pull requests.

1. Fork the repository.
2. Create a feature branch:
   ```bash
   git checkout -b feature-name
   ```
3. Commit your changes:
   ```bash
   git commit -m "Add new feature"
   ```
4. Push to the branch:
   ```bash
   git push origin feature-name
   ```
5. Open a pull request.

---

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Contact
- 🖥️ Portfolio: [karthik-s-sathyan.vercel.app](https://karthik-s-sathyan.vercel.app)
- 💻 GitHub: [Karthikdude](https://github.com/Karthikdude)



