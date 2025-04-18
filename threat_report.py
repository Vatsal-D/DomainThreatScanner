import requests
from urllib.parse import urlparse
from fpdf import FPDF

API_KEY = "c10060dfe432faf28e1f96cdbc0de7e9726765c7819bc019d8728bbcabe48cfd"

def extract_domain(input_value):
    parsed = urlparse(input_value)
    host = parsed.netloc if parsed.netloc else parsed.path
    # Remove port number if present
    return host.split(':')[0]

def get_vt_url(domain_or_ip):
    if all(c.isdigit() or c == '.' for c in domain_or_ip):  # IP check
        return f"https://www.virustotal.com/api/v3/ip_addresses/{domain_or_ip}"
    else:
        return f"https://www.virustotal.com/api/v3/domains/{domain_or_ip}"

def fetch_virustotal_data(domain_or_ip):
    url = get_vt_url(domain_or_ip)
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        print(f"❌ Failed to get data for {domain_or_ip}. Status Code: {response.status_code}")
        return None
    return response.json().get("data", {}).get("attributes", {})

def generate_pdf_report(domain_or_ip, info):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=14)
    pdf.cell(200, 10, txt="Threat Intelligence Report", ln=True, align='C')
    pdf.ln(10)

    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"Target: {domain_or_ip}", ln=True)
    pdf.ln(5)

    for key, value in info.items():
        pdf.set_font("Arial", 'B', size=12)
        pdf.cell(200, 10, txt=f"{key}:", ln=True)
        pdf.set_font("Arial", size=12)
        if isinstance(value, dict):
            for k, v in value.items():
                pdf.cell(200, 10, txt=f"   {k}: {v}", ln=True)
        else:
            pdf.multi_cell(200, 10, txt=str(value))
        pdf.ln(5)

    safe_filename = domain_or_ip.replace('.', '_').replace(':', '_')
    filename = f"Threat_Report_{safe_filename}.pdf"
    pdf.output(filename)
    print(f"✅ PDF report saved as {filename}")

def main():
    user_input = input("Enter domains, IPs, or URLs (comma-separated):\n> ")
    items = [x.strip() for x in user_input.split(',') if x.strip()]

    for item in items:
        domain_or_ip = extract_domain(item)
        print(f"\n🔍 Fetching threat data for: {domain_or_ip}")
        info = fetch_virustotal_data(domain_or_ip)
        if info:
            generate_pdf_report(domain_or_ip, info)

if __name__ == "__main__":
    main()
