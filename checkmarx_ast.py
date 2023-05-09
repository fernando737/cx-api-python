import requests
import json
import argparse

# Configuration
base_url = "https://api.checkmarx.net/ast"
headers = {
    "Content-Type": "application/json"
}

# Function to get projects
def get_projects():
    url = f"{base_url}/projects"
    response = requests.get(url, headers=headers)
    return response.json()
    
# Function to get project ID by name
def get_project_id_by_name(project_name):
    projects = get_projects()
    for project in projects:
        if project["name"] == project_name:
            return project["id"]
    return None
    
# Function to get application ID by name
def get_application_id_by_name(application_name):
    applications = get_applications()
    for application in applications:
        if application["name"] == application_name:
            return application["id"]
    return None

# Function to get applications
def get_applications():
    url = f"{base_url}/applications"
    response = requests.get(url, headers=headers)
    return response.json()
    
# Function to create a project
def create_project(project_name):
    url = f"{base_url}/projects"
    data = {
        "name": project_name
    }
    response = requests.post(url, headers=headers, data=json.dumps(data))
    return response.json()

# Function to upload a file to a project
def upload_file(project_id, file_path):
    url = f"{base_url}/projects/{project_id}/source"
    with open(file_path, "rb") as file:
        response = requests.post(url, headers=headers, files={"file": file})
    return response.json()

# Function to start a security scan
def start_scan(project_id):
    url = f"{base_url}/scans"
    data = {
        "projectId": project_id,
        "preset": "Checkmarx Default"
    }
    response = requests.post(url, headers=headers, data=json.dumps(data))
    return response.json()

# Function to get scan results
def get_scan_results(scan_id):
    url = f"{base_url}/scans/{scan_id}/results"
    response = requests.get(url, headers=headers)
    return response.json()

# Function to update a specific project's group
def update_project_group(project_id, group_id):
    url = f"{base_url}/projects/{project_id}"
    data = {
        "groupId": group_id
    }
    response = requests.put(url, headers=headers, data=json.dumps(data))
    return response.json()

def main(args):
    api_key = input("Please enter your API key: ")
    headers["Authorization"] = f"Bearer {api_key}"

    if args.get_projects:
        projects = get_projects()
        print("Existing projects:")
        for project in projects:
            print(f"{project['id']} - {project['name']}")

    if args.create_project:
        new_project = create_project(args.create_project)
        print(f"Project created: {new_project['id']} - {new_project['name']}")

    if args.upload_file and args.project_id:
        upload_response = upload_file(args.project_id, args.upload_file)
        print("File uploaded:", upload_response)

    if args.start_scan and args.project_id:
        scan = start_scan(args.project_id)
        print(f"Scan started: {scan['id']}")

    if args.get_scan_results and args.scan_id:
        scan_results = get_scan_results(args.scan_id)
        print("Scan results:")
        for result in scan_results:
            print(f"{result['severity']}: {result['name']} - {result['description']}")

    if args.update_project_group and args.project_id:
        updated_project = update_project_group(args.project_id, args.update_project_group)
        print(f"Project updated: {updated_project['id']} - Group: {updated_project['groupId']}")
        
     if args.get_project_id:
        project_id = get_project_id_by_name(args.get_project_id)
        if project_id:
            print(f"Project ID: {project_id}")
        else:
            print("Project not found")

    if args.get_application_id:
        application_id = get_application_id_by_name(args.get_application_id)
        if application_id:
            print(f"Application ID: {application_id}")
        else:
            print("Application not found")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Interact with Checkmarx AST API")
    parser.add_argument("--get-projects", action="store_true", help="Get projects")
    parser.add_argument("--create-project", metavar="NAME", help="Create a new project")
    parser.add_argument("--upload-file", metavar="FILE", help="Upload a file to the project (requires --project-id)")
    parser.add_argument("--start-scan", action="store_true", help="Start a security scan (requires --project-id)")
    parser.add_argument("--get-scan-results", action="store_true", help="Get scan results (requires --scan-id)")
    parser.add_argument("--update-project-group", metavar="GROUP_ID", help="Update a specific project's group (requires --project-id)")
    parser.add_argument("--project-id", metavar="ID", help="Project ID for specific operations")
    parser.add_argument("--scan-id", metavar="ID", help="Scan ID to get results")
    parser.add_argument("--get-project-id", metavar="NAME", help="Get project ID using project name")
    parser.add_argument("--get-application-id", metavar="NAME", help="Get application ID using application name"

    args = parser.parse_args()
    main(args)
