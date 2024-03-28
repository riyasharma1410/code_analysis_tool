from flask import Flask, request, jsonify
from flask_cors import CORS

import re
import base64
import requests
import importlib
import importlib.metadata
import importlib.resources

app = Flask(__name__)
CORS(app, origins=['http://127.0.0.1:5500'])

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

def check_typosquatting(package_name):
    response = requests.get(f"https://pypi.org/pypi/{package_name}/json")
    if response.status_code == 200:
        return 0  # No typosquatting found
    else:
        return 1  # Typosquatting detected

def check_supply_chain_attack(package_name):
    try:
        distribution = importlib.metadata.distribution(package_name)
        # Check if the distribution has a 'Record' entry in its metadata
        if 'Record' in distribution.metadata:
            return 0  # No supply chain attack detected
        else:
            return 1  # Supply chain attack detected
    except importlib.metadata.PackageNotFoundError:
        return 1  # Package not found

def check_code_injection(package_name):
    try:
        distribution = importlib.metadata.distribution(package_name)
        for file_path in distribution.metadata['record']:
            if file_path.endswith(".py"):
                file_content = importlib.resources.read_text(distribution.name, file_path)
                if "exec(" in file_content or "eval(" in file_content:
                    return 1  # Code injection detected
        return 0  # No code injection found
    except (importlib.metadata.PackageNotFoundError, Exception):
        return 1  # Package not found or file not found

def check_credential_harvesting(package_name):
    try:
        distribution = importlib.metadata.distribution(package_name)
        metadata_files = [importlib.resources.read_text(distribution.name, file_path)
                          for file_path in distribution.metadata.get_all('METADATA')]

        if not metadata_files:
            return 1  # Metadata not found

        for metadata_content in metadata_files:
            if "username" in metadata_content.lower() and "password" in metadata_content.lower():
                return 1  # Credential harvesting detected
        return 0  # No credential harvesting found

    except (importlib.metadata.PackageNotFoundError, Exception):
        return 1  # Package not found or file not found

def calculate_package_vulnerability_percentage(package_name):
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
