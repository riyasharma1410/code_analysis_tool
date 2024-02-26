import requests
import pkg_resources
import email.message

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
        print(f"Package '{package_name}' found on PyPI.")
    else:
        print(f"Warning: Possible typosquatting for '{package_name}'. Check the spelling.")

def check_supply_chain_attack(package_name):
    try:
        distribution = pkg_resources.get_distribution(package_name)
        if hasattr(distribution, 'in_toto_metadata'):
            print(f"Package '{package_name}' has in-toto metadata. Supply chain integrity may be verified.")
        else:
            print(f"Warning: Package '{package_name}' may be susceptible to supply chain attacks.")
    except pkg_resources.DistributionNotFound:
        print(f"Package '{package_name}' not found.")

def check_code_injection(package_name):
    try:
        distribution = pkg_resources.get_distribution(package_name)
        print(distribution)
        for file_path in distribution.get_metadata_lines('RECORD'):
            #print(file_path)
            filePath = "./venv/lib/python3.11/site-packages/" + file_path.split(",")[0]
            #print(filePath)
            if filePath.endswith(".py"):
                with open(filePath, 'r') as file:
                    #print(filePath)
                    content = file.read()
                    if "exec(" in content or "eval(" in content:
                        print(f"Warning: Potential code injection detected in package '{package_name}'.")
                        return
                    else:
                        print("no code injection in this file.")
    except pkg_resources.DistributionNotFound:
        print(f"Package '{package_name}' not found.")

def check_credential_harvesting(package_name):
    try:
        distribution = pkg_resources.get_distribution(package_name)
        metadata_files = distribution.get_metadata_lines('METADATA')

        if not metadata_files:
            print(f"Warning: 'METADATA' not found for package '{package_name}'.")
            return

        for file_content in metadata_files:
            # Parse the METADATA file content as an email message
            metadata_message = email.message_from_string(file_content)
            # Check for common credential harvesting patterns in the description
            if "username" in str(metadata_message).lower() and "password" in str(metadata_message).lower():
                print(f"Warning: Potential credential harvesting detected in package '{package_name}'.")
                return
        print(f"No Potential credential harvesting detected in package '{package_name}'.")
        return

    except pkg_resources.DistributionNotFound:
        print(f"Package '{package_name}' not found.")

def reformatString(name):
    # Replace '>=', '<', ',' and '>' with space, then split by space
    parts = [part.strip() for part in name.replace('>=', ' ').replace('<', ' ').replace(',', ' ').replace('>', ' ').split()][0]
    
    # Check if '>=', '<', or '>' are present, and adjust the package name accordingly
    if '>=' in parts:
        # Find the index of '>=' and take the substring before it as the package name
        parts = parts.strip()
    return parts

if __name__ == "__main__":
    installed = get_installed_packages()
    print(installed)
    for pkg in installed:
        dep = get_dependent_packages(pkg)
        if len(dep) > 0:
            for part in dep:
                newPart = reformatString(part)
                check_typosquatting(newPart)
                check_credential_harvesting(newPart)
                check_code_injection(newPart)
                check_supply_chain_attack(newPart)