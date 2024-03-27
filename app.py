from flask import Flask, request, jsonify
from flask_cors import CORS, cross_origin
import re
import base64
import requests
import importlib.metadata as metadata
from packaging.requirements import Requirement
import pkg_resources
import email.message

app = Flask(__name__)
cors = CORS(app, origins=['http://127.0.0.1:5500'])
app.config['CORS_HEADERS'] = 'Content-Type'

def get_repository_dependencies(repo_url):
    match = re.match(r'https://github.com/([^/]+)/([^/]+)', repo_url)
    if match:
        username, repo_name = match.groups()
    else:
        return []

    api_url = f"https://api.github.com/repos/{username}/{repo_name}/contents/requirements.txt"
    response = requests.get(api_url)
    if response.status_code == 200:
        requirements_content = response.json().get("content", "")
        requirements_content = base64.b64decode(requirements_content).decode("utf-8")
        dependencies = [line.strip() for line in requirements_content.split("\n") if line.strip()]
        return dependencies
    else:
        return []

def get_installed_packages():
    installed_packages = []
    for distribution in pkg_resources.working_set:
        installed_packages.append(distribution.project_name)
    return installed_packages

def get_dependent_packages(package_name):
    try:
        distribution = pkg_resources.get_distribution(package_name)
        dependencies = [str(req) for req in distribution.requires()]
        return dependencies
    except pkg_resources.DistributionNotFound:
        return []

def check_typosquatting(package_name):
    response = requests.get(f"https://pypi.org/pypi/{package_name}/json")
    if response.status_code == 200:
        return 0  # No typosquatting found
    else:
        return 1  # Typosquatting detected

def check_supply_chain_attack(package_name):
    try:
        distribution = pkg_resources.get_distribution(package_name)
        if hasattr(distribution, 'in_toto_metadata'):
            return 0  # No supply chain attack detected
        else:
            return 1  # Supply chain attack detected
    except pkg_resources.DistributionNotFound:
        return 1  # Package not found

def check_code_injection(package_name):
    try:
        distribution = pkg_resources.get_distribution(package_name)
        for file_path in distribution.get_metadata_lines('RECORD'):
            filePath = "./venv/lib/python3.11/site-packages/" + file_path.split(",")[0]
            if filePath.endswith(".py"):
                with open(filePath, 'r') as file:
                    content = file.read()
                    if "exec(" in content or "eval(" in content:
                        return 1  # Code injection detected
        return 0  # No code injection found
    except pkg_resources.DistributionNotFound:
        return 1  # Package not found

def check_credential_harvesting(package_name):
    try:
        distribution = pkg_resources.get_distribution(package_name)
        metadata_files = distribution.get_metadata_lines('METADATA')

        if not metadata_files:
            return 1  # Metadata not found

        for file_content in metadata_files:
            metadata_message = email.message_from_string(file_content)
            if "username" in str(metadata_message).lower() and "password" in str(metadata_message).lower():
                return 1  # Credential harvesting detected
        return 0  # No credential harvesting found

    except pkg_resources.DistributionNotFound:
        return 1  # Package not found

def reformatString(name):
    parts = [part.strip() for part in name.replace('>=', ' ').replace('<', ' ').replace(',', ' ').replace('>', ' ').split()][0]
    if '>=' in parts:
        parts = parts.strip()
    return parts

def calculate_package_vulnerability_percentage(package_name):
    # Perform all vulnerability checks and calculate the total percentage
    checks = [
        check_typosquatting(package_name),
        check_supply_chain_attack(package_name),
        check_code_injection(package_name),
        check_credential_harvesting(package_name)
    ]
    total_checks = len(checks)
    total_vulnerabilities = sum(check for check in checks)
    if total_checks > 0:
        return (total_vulnerabilities / total_checks) * 100
    else:
        return 0

@app.route('/analyze', methods=['POST'])
#@cross_origin()
def analyze_repository():
    repo_url = request.form.get('repo_url')
    dependencies = get_repository_dependencies(repo_url)
    
    if dependencies:
        total_vulnerability_percentage = 0
        total_packages = len(dependencies)
        vulnerabilities = []

        for package_name in dependencies:
            vulnerability_percentage = calculate_package_vulnerability_percentage(package_name)
            total_vulnerability_percentage += vulnerability_percentage
            vulnerabilities.append({"package_name": package_name, "vulnerability_percentage": vulnerability_percentage})

        if total_packages > 0:
            total_vulnerability_percentage /= total_packages
            return jsonify({
                "total_vulnerability_percentage": total_vulnerability_percentage,
                "dependencies": vulnerabilities
            })
        else:
            return jsonify({"message": "No dependencies found in the repository."}), 400
    else:
        return jsonify({"message": "No dependencies found in the repository."}), 400

if __name__ == "__main__":
    app.run(port=8000, debug=True)
