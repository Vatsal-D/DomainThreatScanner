import requests
from fpdf import FPDF

# Replace with your actual VirusTotal API key
API_KEY = "c10060dfe432faf28e1f96cdbc0de7e9726765c7819bc019d8728bbcabe48cfd"
headers = {
    "x-apikey": API_KEY
}

#Get multiple domains from user input
input_domains = input("Enter domain(s) separated by commas (e.g., google.com, youtube.com): ")
domains = [d.strip() for d in input_domains.split(",") if d.strip()]

#Loop through each domain
for domain in domains:
    print(f"\n🔍 Fetching data for: {domain}")
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print(f" Failed to get data for {domain}. HTTP Error: {err}")
        continue
    except Exception as e:
        print(f" Unexpected error for {domain}: {e}")
        continue

    data = response.json()
    attributes = data.get("data", {}).get("attributes", {})

    #Create PDF report
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=16)
    pdf.cell(200, 10, "Threat Intelligence Report", ln=True, align='C')
    pdf.ln(10)

    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, f"Domain: {domain}", ln=True)
    pdf.ln(5)

    for key, value in attributes.items():
        pdf.set_font("Arial", 'B', size=12)
        pdf.cell(200, 10, f"{key}:", ln=True)
        pdf.set_font("Arial", size=12)

        if isinstance(value, dict):
            for sub_key, sub_value in value.items():
                pdf.multi_cell(0, 10, f"   {sub_key}: {sub_value}")
        elif isinstance(value, list):
            for item in value:
                pdf.multi_cell(0, 10, f"   - {item}")
        else:
            pdf.multi_cell(0, 10, str(value))

        pdf.ln(3)

    #Save PDF
    filename = f"Threat_Report_{domain.replace('.', '_')}.pdf"
    pdf.output(filename)
    print(f" Report saved: {filename}")
