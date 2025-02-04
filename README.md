# OS Security Risk Assessment Tool 🛡️

An automated security risk assessment tool for analyzing operating system vulnerabilities, patch statuses, and end-of-life risks.

[![Python](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## 🔍 Overview

This tool performs comprehensive security risk assessments for multiple operating systems by analyzing:
- CVEs from the National Vulnerability Database
- CISA's Known Exploited Vulnerabilities (KEVs)
- Patch availability status
- End-of-life timelines
- System update status

## ✨ Features

- 🔄 Real-time CVE data retrieval and analysis
- 📊 Risk score calculation based on multiple security factors
- 💾 Smart caching system for efficient API usage
- 📝 Detailed Excel reports with risk highlighting
- 🔧 Configurable risk weights and assessment parameters
- 📈 Support for multiple operating systems

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/os-security-assessment.git
cd os-security-assessment

# Install dependencies
pip install -r requirements.txt

# Copy and configure settings
cp config.example.ini config.ini
```

## ⚙️ Configuration

Edit `config.ini` to customize your assessment:

```ini
[API]
api_key = your_nvd_api_key
nvd_base_url = https://services.nvd.nist.gov/rest/json/cves/2.0
kev_url = https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

[Cache]
cache_dir = os_risk_cache
cache_duration_days = 7
force_refresh = False

[RiskWeights]
cvss_score = 0.25
high_severity = 0.20
kev_status = 0.20
patch_availability = 0.15
eol_status = 0.15
latest_patch = 0.05
```

## 📊 Risk Scoring Matrix

### Weight Distribution (100%)

| Factor | Weight | Description |
|--------|---------|-------------|
| CVSS Score | 25% | Average CVSS score normalized to 0-100 |
| High Severity CVEs | 20% | Count of CVEs with CVSS ≥7.0 (max 10) |
| KEV Status | 20% | Known Exploited Vulnerabilities (max 5) |
| Patch Availability | 15% | Based on patch release frequency |
| End-of-Life Status | 15% | Days until EOL date (365 days window) |
| Latest Patch | 5% | Penalty for limited/no patches |

### Risk Levels

| Score Range | Risk Level | Color Code |
|-------------|------------|------------|
| ≥80 | Critical | 🔴 Red |
| ≥60 | High | 🟠 Orange |
| ≥40 | Medium | 🟡 Yellow |
| <40 | Low | 🟢 Green |

### Component Calculations

#### Patch Availability Weights
- Regular Patches: 0.2 (lowest risk)
- Limited Patches: 0.6 (medium risk)
- No Patches: 1.0 (highest risk)

#### EOL Status
```
EOL_Score = max(0, min(1.0, 1 - (days_until_eol / 365))) * weight * 100
```

## 🚀 Usage

```bash
python analyze_cache.py
```

The tool will:
1. Load configuration settings
2. Retrieve and cache vulnerability data
3. Calculate risk scores
4. Generate `os_security_assessment.xlsx`

## 📘 Report Format

The Excel report includes:
- Operating System details
- CVE statistics and counts
- High severity vulnerability lists
- KEV tracking information
- Patch availability status
- End-of-life dates
- Color-coded risk scores

## 🗄️ Cache Management

- CVE data cached for configured duration
- Automatic cache cleanup
- Force refresh option available
- Cache directory structure:
  ```
  os_risk_cache/
  ├── cves/
  │   └── [os_hash].json
  └── kev/
      └── kev_catalog.json
  ```

## 📝 Logging

All operations are logged to `os_risk_assessment.log`:
- API interactions
- Cache operations
- Data processing steps
- Error conditions
- Report generation status

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

## ⚠️ Disclaimer

This tool is provided as-is for security assessment purposes. Always verify results and consult security professionals for critical systems.

## 📚 Dependencies

Main dependencies:
- `requests`: API communication
- `pandas`: Data processing
- `openpyxl`: Excel report generation
- `tqdm`: Progress tracking
- `configparser`: Configuration management

## 🙏 Acknowledgments

- National Vulnerability Database (NVD)
- CISA KEV Catalog
- Contributing developers

---
*Last updated: February 2025*
