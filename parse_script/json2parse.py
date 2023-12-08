import json
import pandas as pd

with open('/Users/isaac/Downloads/CVEfixes_v1.0.7/Data/json/nvdcve-1.1-2005.json', 'r') as f:
    data = json.load(f)

# Extract the relevant ipwdnformation for the project
cve_items = data.get('CVE_Items', [])
rows = []
# Set the functions for the CVE variables. 
for item in cve_items:
    cve = item.get('cve', {})
    cve_id = cve['CVE_data_meta']['ID']
    cvss_v2 = item.get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {})
    severity = item.get('impact', {}).get('baseMetricV2', {}).get('severity', 'N/A')

    # Appending the data we require 
    rows.append({
        'ID': cve_id,
        'Version': cvss_v2.get('version', 'N/A'),
        'VectorString': cvss_v2.get('vectorString', 'N/A'),
        'AccessVector': cvss_v2.get('accessVector', 'N/A'),
        'AccessComplexity': cvss_v2.get('accessComplexity', 'N/A'),
        'Authentication': cvss_v2.get('authentication', 'N/A'),
        'ConfidentialityImpact': cvss_v2.get('confidentialityImpact', 'N/A'),
        'IntegrityImpact': cvss_v2.get('integrityImpact', 'N/A'),
        'AvailabilityImpact': cvss_v2.get('availabilityImpact', 'N/A'),
        'BaseScore': cvss_v2.get('baseScore', 'N/A'),
        'Severity': severity,
        'ExploitabilityScore': item.get('impact', {}).get('baseMetricV2', {}).get('exploitabilityScore', 'N/A'),
        'ImpactScore': item.get('impact', {}).get('baseMetricV2', {}).get('impactScore', 'N/A'),
        'ACInsufInfo': item.get('impact', {}).get('baseMetricV2', {}).get('acInsufInfo', False),
        'ObtainAllPrivilege': item.get('impact', {}).get('baseMetricV2', {}).get('obtainAllPrivilege', False),
        'ObtainUserPrivilege': item.get('impact', {}).get('baseMetricV2', {}).get('obtainUserPrivilege', False),
        'ObtainOtherPrivilege': item.get('impact', {}).get('baseMetricV2', {}).get('obtainOtherPrivilege', False),
        'UserInteractionRequired': item.get('impact', {}).get('baseMetricV2', {}).get('userInteractionRequired', False),
    })

# Create DataFrame 
df = pd.DataFrame(rows)

# Save DataFrame to CSV file format to be easy to use for model training
df.to_csv('output_cve_2005.csv', index=False)
