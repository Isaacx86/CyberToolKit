from flask import Flask, render_template, request, jsonify
import shodan
import requests
import time
import joblib
import pandas as pd
import os
import socket

SHODAN_API_KEY = 'LDAxkgwomLK17x6VFVGUhiNZ6ZlWUktz'
MODEL_PATH = 'final_model_CVE.joblib'
CSV_FILE_PATH = 'output_cve_2020.csv'
NVD_API_KEY= '2a5467cd-1a42-451f-ab2f-dd356ecb7f7c'

final_model = joblib.load(MODEL_PATH)
csv_data = pd.read_csv(CSV_FILE_PATH)

app = Flask(__name__)

def generate_firewall_rules(open_ports, action, filter_ip, os_type):
    firewall_rules = []

    for port in open_ports:
        firewall_rule = generate_firewall_rule(port, action, filter_ip, os_type)
        firewall_rules.append(firewall_rule)

    return firewall_rules

def generate_firewall_rule(port, action, filter_ip, os_type):
    if os_type.lower() == 'linux':
        if action.lower() == 'allow':
            return f"iptables -A INPUT -p tcp --dport {port} -j ACCEPT"
        elif action.lower() == 'block':
            return f"iptables -A INPUT -p tcp --dport {port} -j DROP"
        elif action.lower() == 'filter' and filter_ip:
            return f"iptables -A INPUT -p tcp --dport {port} -s {filter_ip} -j ACCEPT"
        else:
            return 'Unsupported action'
    elif os_type.lower() == 'windows':
        if action.lower() == 'allow':
            return f"netsh advfirewall firewall add rule name='Allow Port {port}' dir=in action=allow protocol=TCP localport={port}"
        elif action.lower() == 'block':
            return f"netsh advfirewall firewall add rule name='Block Port {port}' dir=in action=block protocol=TCP localport={port}"
        elif action.lower() == 'filter' and filter_ip:
            return f"netsh advfirewall firewall add rule name='Filter Port {port}' dir=in action=allow protocol=TCP localport={port} remoteip={filter_ip}"
        else:
            return 'Unsupported action'
    elif os_type.lower() == 'osx':
        if action.lower() == 'allow':
            return f"pass in proto tcp from any to any port {port}"
        elif action.lower() == 'block':
            return f"block in proto tcp from any to any port {port}"
        elif action.lower() == 'filter' and filter_ip:
            return f"pass in proto tcp from {filter_ip} to any port {port}"
        else:
            return 'Unsupported action'
    else:
        return 'Unsupported operating system'
    

def fill_data_for_cve(cve_id, year):
    csv_file_path = f'output_cve_{year}.csv'
    if os.path.exists(csv_file_path):
        csv_data = pd.read_csv(csv_file_path)
        if cve_id in csv_data['ID'].values:
            csv_row = csv_data[csv_data['ID'] == cve_id].iloc[0]
        new_data = pd.DataFrame({
            'ID': [cve_id],
            'Version': [csv_row['Version']],
            'AccessVector': [csv_row['AccessVector']],
            'AccessComplexity': [csv_row['AccessComplexity']],
            'Authentication': [csv_row['Authentication']],
            'ConfidentialityImpact': [csv_row['ConfidentialityImpact']],
            'IntegrityImpact': [csv_row['IntegrityImpact']],
            'AvailabilityImpact': [csv_row['AvailabilityImpact']],
            'BaseScore': [csv_row['BaseScore']],
            'Severity': [csv_row['Severity']],
            'ExploitabilityScore': [csv_row['ExploitabilityScore']],
            'ImpactScore': [csv_row['ImpactScore']],
            'ACInsufInfo': [csv_row['ACInsufInfo']],
            'ObtainAllPrivilege': [csv_row['ObtainAllPrivilege']],
            'ObtainUserPrivilege': [csv_row['ObtainUserPrivilege']],
            'ObtainOtherPrivilege': [csv_row['ObtainOtherPrivilege']],
            'UserInteractionRequired': [csv_row['UserInteractionRequired']]
        })
        return new_data
    else:
        return pd.DataFrame()
def clean_data_for_serialization(data):
    # Exclude any non-serializable keys from the data
    return {key: value for key, value in data.items() if not callable(value)}

def get_cve_info_list(host_info):
    cve_info_list = []
    if 'vulns' in host_info:
        for cve in host_info['vulns']:
            print(f"Sleeping before request for CVE {cve}")
            time.sleep(5)
            response = requests.get(f'https://services.nvd.nist.gov/rest/json/cve/1.0/{cve}?api_key={NVD_API_KEY}')
            if response.status_code == 200:
                cve_info_data = fill_data_for_cve(cve)
                cve_info_data['HostInfo'] = clean_data_for_serialization(host_info)
                cve_info_data['NVDData'] = response.json()
                cve_info_list.append(cve_info_data.to_dict())
            else:
                cve_info_list.append({"Error": "Error Retrieving the data from NIST"})
    return cve_info_list
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        input_value = request.form.get('input_value')

        try:
            # Check if the input is an IP address
            ip_address = socket.inet_aton(input_value)
        except socket.error:
            # If it's not a valid IP address, treat it as a hostname
            ip_address = socket.gethostbyname(input_value)

        # Convert the IP address to a string
        ip_address = socket.inet_ntoa(ip_address) if isinstance(ip_address, bytes) else ip_address

        # Rest of your existing code
        SHODAN_API_KEY = 'LDAxkgwomLK17x6VFVGUhiNZ6ZlWUktz'
        api = shodan.Shodan(SHODAN_API_KEY)

        try:
            host_info = api.host(ip_address)
            return render_template('results.html', host_info=host_info)
        except shodan.APIError as e:
            return f'Shodan Error: {e}'
        except Exception as ex:
            return f'An error occurred: {ex}'
    return render_template('index.html')
@app.route('/cve_info', methods=['POST'])
def cve_info():
    ip_address = request.form.get('ip_address')
    api = shodan.Shodan(SHODAN_API_KEY)
    try:
        host_info = api.host(ip_address)
        cve_info_list = []  # Use a list instead of a dictionary
        if 'vulns' in host_info:
            for cve in host_info['vulns']:
                year = cve.split('-')[1]
                print(f"Sleeping before request for CVE {cve}")
                time.sleep(2)
                response = requests.get(f'https://services.nvd.nist.gov/rest/json/cve/1.0/{cve}')
                if response.status_code == 200:
                    cve_data = fill_data_for_cve(cve, year)
                    if cve_data.empty:
                        print(f"Skipping CVE {cve}: No data found.")
                        continue
                    vulnerability_score = final_model.predict(cve_data)
                    cve_info = {
                        'CVE': cve,
                        'NVDData': response.json(),
                        'VulnerabilityScore': vulnerability_score[0]
                    }
                    cve_info_list.append(cve_info)  # Append to the list
                    print(f"Processed CVE: {cve}")
                else:
                    print(f"Error retrieving data for CVE {cve}: {response.status_code}")
                    cve_info_list.append({
                        'CVE': cve,
                        'Error': f"Error retrieving data for CVE {cve}: {response.status_code}"
                    })

        return jsonify(cve_info_list)
    except shodan.APIError as e:
        return jsonify(error=str(e))
    except Exception as ex:
        return jsonify(error=str(ex))
api = shodan.Shodan(SHODAN_API_KEY)

def get_open_ports(ip_address):
    try:
        result = api.host(ip_address)
        open_ports = [str(port) for port in result['ports']]
        return open_ports
    except shodan.exception.APIError as e:
        return str(e)

@app.route('/generate_rule', methods=['POST'])
def generate_rule():
    try:
        ip_address = request.form.get('ip_address')
        action = request.form.get('action')
        filter_ip = request.form.get('filter_ip')
        os_type = request.form.get('os_type')

        # Check if the IP address is valid before proceeding

        open_ports = get_open_ports(ip_address)

        # Generate firewall rules based on open ports
        firewall_rules = [
            generate_firewall_rule(port, action, filter_ip, os_type)
            for port in open_ports
        ]

        return jsonify(firewall_rules=firewall_rules)

    except Exception as e:
        print(f"Error: {e}")
        return jsonify(error=str(e)), 500  # Return error response with HTTP status code 500

if __name__ == '__main__':
    app.run(debug=True)