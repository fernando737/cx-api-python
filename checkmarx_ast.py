import requests
import json
import argparse

# Configuration
base_url = "https://eu.ast.checkmarx.net/api"
base_url_auth = "https://eu.ast.checkmarx.net/auth"

headers = {
    "Content-Type": "application/json"
}

# Function to get access token
def get_access_token(tenant_name, api_key):
    token_url = f"https://eu.iam.checkmarx.net/auth/realms/adidas/protocol/openid-connect/token"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }
    data = {
        "grant_type": "refresh_token",
        "client_id": "ast-app",
        "refresh_token": api_key
    }
    response = requests.post(token_url, headers=headers, data=data)

    # Print the response status code and JSON response for debugging
    print("Status code:", response.status_code)
    print("JSON response:", response.json())

    if response.status_code == 200:
        return response.json()["access_token"]
    else:
        raise Exception("Failed to get access token. Please check your credentials and try again.")




# Function to get projects
def get_projects():
    url = f"{base_url}/projects"
    response = requests.get(url, headers=headers)

    json_response = response.json()
    return json_response['projects']  # Return the list of projects
    
# Function to get project ID by name
#++++++++++++++++++++++++++++++++++++
#++++++++++++++++++++++++++++++++++++
def get_project_id(project_name):
    projects = get_projects()
    for project in projects:
        print(project["name"])
        print("----"+project_name)
        if project["name"] == project_name:
            return project["id"]
    return None

# Function to get project ID by name
def get_groups_by_project(project_name):
    projects = get_projects()
    for project in projects:
        print(project["name"])
        print(project["groups"])
        if project["name"].lower() == project_name.lower():
            return project["id"]
    return None
    
# Function to get application ID by name
def get_application_id_by_name(application_name):
    applications = get_applications()
    
    for application in applications:
        print(application["name"])
        print("--------------")
        print(application_name)
        if application["name"] == application_name:  # Convert both names to lowercase before comparing
            return application["id"]
    return None

# Function to get applications
def get_applications():
    url = f"{base_url}/applications"
    response = requests.get(url, headers=headers)

    json_response = response.json()
    return json_response['applications']  # Return the list of applications
    
# Function to create a project
def create_project(project_name):
    url = f"{base_url}/projects"
    data = {
        "name": project_name
    }
    response = requests.post(url, headers=headers, data=json.dumps(data))
    return response.json()

# Function to upload a file to a project
def request_upload_url():
    url = f"{base_url}/uploads"
    response = requests.post(url, headers=headers)
    return response.json()['url']

def upload_and_scan_file_to_presigned_url(file_path,project_id):
    presigned_url = request_upload_url()
    with open(file_path, 'rb') as file:
       response_upload = requests.put(presigned_url, data=file)
    
    if response_upload.status_code == 200:
       print("File uploaded successfully.")
    else:
       print(f"Error uploading file: {response_upload.status_code} {response_upload.text}")
    return response_upload

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

# Function to get group ID by name
def get_group_id(group_name):
    url = f'{base_url_auth}/groups'
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        groups = response.json()
        for group in groups:
            if group['name'].lower() == group_name.lower():
                print(group['id'])
                return group['id']
        print(f"No group found with the name '{group_name}'")
    else:
        print(f"Error searching for group '{group_name}': {response.status_code} {response.text}")
    return None

# Function to update a specific project's group
def update_project_group(project_id, group_name):
    url = f"{base_url}/projects/{project_id}"
    data = {
        "groupId": get_group_id(group_name)
    }
    response = requests.put(url, headers=headers, data=json.dumps(data))
    print(response.json())

    return response.json()

# Function to get projects by application name
def get_projects_by_application_name(application_name):
    application_id = get_application_id_by_name(application_name)
    if application_id is None:
        return None

    projects = get_projects()
    associated_projects = [project for project in projects if project["applicationId"] == application_id]
    return associated_projects

def main(args):
    tenant_name = input("Please enter your tenant name: ")
    api_key = input("Please enter your API key: ")

    access_token = get_access_token(tenant_name, api_key)
    headers["Authorization"] = f"Bearer {access_token}"

    if args.get_projects:
        projects = get_projects()
        print("Existing projects:")
        for project in projects:
            print(f"{project['id']} - {project['name']}")
    
    if args.get_project_id:
        project_id = get_project_id(args.get_project_id)
        print(project_id)
        if project_id:
            print(f"Project ID: {project_id}")
        else:
            print("Project not found")

    if args.create_project:
        new_project = create_project(args.create_project)
        print(f"Project created: {new_project['id']} - {new_project['name']}")

    if args.get_groups_by_project:
        groups = get_groups_by_project(args.get_groups_by_project)
        print(f"Project groups: {groups}")

    if args.upload_file and args.project_id:
        upload_response = upload_and_scan_file_to_presigned_url( args.upload_file,args.project_id,)
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
        
    

    if args.get_application_id:
        application_id = get_application_id_by_name(args.get_application_id)
        if application_id:
            print(f"Application ID: {application_id}")
        else:
            print("Application not found")

    if args.get_projects_by_application:
        projects = get_projects_by_application_name(args.get_projects_by_application)
        if projects is not None:
            for project in projects:
                print(f"Project ID: {project['id']}, Project Name: {project['name']}")
        else:
            print("Application not found")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Interact with Checkmarx AST API")
    parser.add_argument("--get-projects", action="store_true", help="Get projects")
    parser.add_argument("--get-project-id", metavar="NAME", help="Get project ID using project name")
    parser.add_argument("--get-groups-by-project", metavar="NAME", help="Get project groups")
    parser.add_argument("--create-project", metavar="NAME", help="Create a new project")
    parser.add_argument("--upload-file", metavar="FILE", help="Upload a file to the project (requires --project-id)")
    parser.add_argument("--start-scan", action="store_true", help="Start a security scan (requires --project-id)")
    parser.add_argument("--get-scan-results", action="store_true", help="Get scan results (requires --scan-id)")
    parser.add_argument("--update-project-group", metavar="GROUP_ID", help="Update a specific project's group (requires --project-id)")
    parser.add_argument("--project-id", metavar="ID", help="Project ID for specific operations")
    parser.add_argument("--scan-id", metavar="ID", help="Scan ID to get results")
    parser.add_argument("--get-application-id", metavar="NAME", help="Get application ID using application name")
    parser.add_argument("--get-projects-by-application", metavar="NAME", help="Get all projects associated with an application name")
    args = parser.parse_args()
    main(args)
