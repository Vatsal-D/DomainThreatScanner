# DomainThreatScanner
DomainThreatScanner is a Python-based tool that allows users to input multiple domain names and retrieve threat intelligence data using the VirusTotal API. It generates professional PDF reports summarizing the security status of each domain, helping security analysts, researchers, and developers stay informed about potential risks.
# Features
- Accepts multiple domains from user input
- Uses the VirusTotal API to gather threat intelligence
- Generates a PDF report for each domain
- Supports malicious, suspicious, and harmless domain info
- Easy to use and lightweight

## How to Use
# 1. Clone the repo
git clone https://github.com/yourusername/DomainThreatScanner.git
cd DomainThreatScanner
# 2. Install Dependencies
pip install requests fpdf
# 3. Set Your VirusTotal API Key
Edit the API_KEY variable in the script:
API_KEY = "your_virustotal_api_key"
Get your API key from https://www.virustotal.com
# 4. Run the Script
python threat_report.py
# 5. Enter Domains in the terminal
You will be prompted to enter multiple domains separated by commas, like this:
google.com, youtube.com, example.com
# 6. View PDF Reports
Reports will be saved as:
Threat_Report_example_com.pdf
