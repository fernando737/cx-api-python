import requests
import json
import argparse
import sys
import time
import threading
import pandas as pd

from requests.exceptions import HTTPError

def spinner(stop_spinner):
    spinner_chars = ['-', '\\', '|', '/']
    i = 0
    while not stop_spinner.is_set():
        sys.stdout.write('\r' + spinner_chars[i % len(spinner_chars)])
        sys.stdout.flush()
        i += 1
        time.sleep(0.1)

# Configuration
base_url = "https://eu.ast.checkmarx.net/api"
base_url_auth = "https://eu.ast.checkmarx.net/auth"

# Initial definition of headers
headers = {
    "Content-Type": "application/json",
    "Authorization": ""
}

# Function to get access token
def get_access_token(tenant_name, api_key):
    token_url = f"https://eu.iam.checkmarx.net/auth/realms/{tenant_name}/protocol/openid-connect/token"
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

    if response.status_code == 200:
        print("[DONE] Access token retrieved successfully.")
        return response.json()["access_token"]
    else:
        raise Exception("Failed to get access token. Please check your credentials and try again.")

# Function to get projects
# [### --get-projects ###]
def get_projects():
    url = f"{base_url}/projects"
    params = {
        "offset" : "0",
        "limit" : "0",
    }
    response = requests.get(url,params=params,headers=headers)
    return response.json()['projects']  # Return the list of projects
    
# Function to get project  by name
# [### --get-projects-by-name ###]
def get_project_by_name(project_name):
    url = f"{base_url}/projects"
    params = {
        "offset" : "0",
        "limit" : "0",
        "name" : project_name
    }
    try:
        response = requests.get(url,params=params,headers=headers)
        return response.json()['projects'][0]  # Return the list of projects
    except HTTPError as e:
        return None
    
# Function to get project  by id
# [### --get-project-by-id ###]
def get_project_by_id(project_id):
    url = f"{base_url}/projects/"
    params = {
        "offset" : "0",
        "limit" : "1",
        "ids" : project_id
    }
    try:
        response = requests.get(url,params=params,headers=headers)
        return response.json()['projects'][0]  # Return the list of projects
    except HTTPError as e:
        return None

# Function to get project groups by id
# [### --get-project-groups-by-id ###]
def get_project_groups_by_id(project_id):
    project = get_project_by_id(project_id)
    if project:
        if len(project['groups']) == 0:
            return 0
        else:
            return project["groups"]
    else:
        return None
    
# Function to get project groups by name
# [### --get-project-groups-by-name ###]
def get_project_groups_by_name(project_name):
    project = get_project_by_name(project_name)
    if project:
        if len(project['groups']) == 0:
            return 0
        else:
            return project["groups"]
    else:
        return None

# Function to get applications
# [### --get-applications ###]
def get_applications():
    url = f"{base_url}/applications"
    params = {
        "offset" : "0",
        "limit" : "0",
    }
    response = requests.get(url, headers=headers, params=params)
    return response.json()['applications']  # Return the list of applications
 
# Function to get application ID by name
# [### --get-application-by-name ###]
def get_application_by_name(application_name):
    url = f"{base_url}/applications"
    params = {
        "offset" : "0",
        "limit" : "1",
        "name" : application_name
    }
    try:
        response = requests.get(url,params=params,headers=headers)
        if len(response.json()['applications']) == 0:
            return None
        else:
            return response.json()['applications'][0]  # Return the list of applications
    except HTTPError as e:
        return None

# Function to get application NAME by id
# [### --get-application-by-id ###]
def get_application_by_id(application_id):
    url = f"{base_url}/applications/{application_id}"
    params = {
        "offset" : "0",
        "limit" : "1",
    }
    try:
        response = requests.get(url,params=params,headers=headers)
        return response.json() # Return the application
    except HTTPError as e:
        return None

# Function to get projects by application name
# [### --get-application-projects-by-name ###]]
def get_application_projects_by_name(application_name):
    application = get_application_by_name(application_name)
    projects = []
    if application:
        if len(application["projectIds"]) == 0:
            return 0
        else:
            for project_id in application["projectIds"]:
                project_name = get_project_by_id(project_id)
                projects.append({"id" : project_id,
                                "name" : project_name['name']})
            return projects
    else:
        return None

# Function to get projects by application id
# [### --get-application-projects-by-id ###]]
def get_application_projects_by_id(application_id):
    application = get_application_by_id(application_id)
    projects = []
    if application:
        if len(application["projectIds"]) == 0:
            return 0
        else:
            for project_id in application["projectIds"]:
                project_name = get_project_by_id(project_id)
                projects.append({"id" : project_id,
                                "name" : project_name['name']})
            return projects
    else:
        return None

# Function to update a specific project's group
# [### --update-project-group-by-id ###]
def update_project_group_by_id(project_id, group_id):
    project = get_project_by_id(project_id)
    if project:
        print(f"[INFO] Current groups {project['groups']}")
        project['groups'].append(group_id)
        project = update_project(project)
        if project:
            return project
        else:
            return 0
    else:
        None

# Function to update a specific project's group
# [### Auxiliary function ###]
def update_project(project):
    url = f"{base_url}/projects/{project['id']}"
    response = requests.put(url, headers=headers, data=json.dumps(project))
    if response.status_code == 204:
        project = get_project_by_id(project['id'])
        return project
    else:
        return None
# Function to get scan result for all projects part of application
# [### Auxiliary function  ###]
def get_application_scans_by_id(application_id):
    # Get the latest scan result for the specified project
    try:
        last_scan_url = f"{base_url}/projects/last-scan"
        params = {
            "offset" : "0",
            "limit" : "0",
            "application-id" : application_id
        }
        last_scan_response = requests.get(last_scan_url, params=params, headers=headers)
        last_scan_response.raise_for_status()
        return last_scan_response.json() # Return the list of projects
    except HTTPError as e:
        last_scan_response = None
    return last_scan_response

# Function to check the progress of sast coverage of an Application
# [### --get-application-progress-sast-by-name ###]
def get_application_progress_sast_by_name(application_name):
    # Get the application ID based on the application name
    application = get_application_by_name(application_name)
    
    if application:
        application_id = application["id"]

        application_scans = get_application_scans_by_id(application_id)
        scanned_projects = 0
        progress = 0
        if application_scans != None and len(application_scans.items()) != 0:
            for uuid, info in application_scans.items():
                if "status" in info:
                    if info["status"] == "Completed":
                        scanned_projects += 1
            progress = (scanned_projects / len(application_scans.items())) * 100
        else:
            progress = 0
        return progress
    else:
        return None
    
# Function to check the scan status of a Project
# [### --get-project-scan-status-by-id ###]
def get_project_scan_status_by_id(project_id):
    # Get the latest scan result for the specified project
    try:
        last_scan_url = f"{base_url}/projects/last-scan"
        params = {
            "offset" : "0",
            "limit" : "1",
            "project-ids" : project_id
        }
        last_scan_response = requests.get(last_scan_url, params=params, headers=headers)
        last_scan_response.raise_for_status()
        return last_scan_response.json() # Return the project
    except HTTPError as e:
        last_scan_response = None
    return last_scan_response

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






########################## MAIN ###########################
def main(args):
    tenant_name = input("Please enter your tenant name: ")
    api_key = input("Please enter your API key: ")

    access_token = get_access_token(tenant_name, api_key)
    headers["Authorization"] = f"Bearer {access_token}"

# [### --get-projects ###]
    if args.get_projects:
        projects = get_projects()
        counter = 0
        data = []

        if projects:
            for project in projects:
                project_scan = get_project_scan_status_by_id(project['id'])
                if project_scan: 
                    status = project_scan[project['id']].get("status", "No scan")
                else: 
                    status = "No scan"
                
                if status == "Completed": 
                    counter += 1 

                data.append({"id": project['id'], "name": project['name'], "status": status, "group": project['groups']})

            print(f"Existing projects : {len(projects)}, Scanned projects : {counter}, Percentage : {counter/len(projects)*100}%")

            # Create a DataFrame from the data list and write it to a CSV
            df = pd.DataFrame(data)
            df.to_csv('projects_data.csv', index=False)
        else:
            print("[ERROR] No projects found")


# [### --get-project-by-name ###]
    if args.get_project_by_name:
        project = get_project_by_name(args.get_project_by_name)
        if project:
            print(project['id'])
        else:
            print(f"[ERROR] Project '{args.get_project_by_name}' was not found")

# [### --get-project-by-id ###]
    if args.get_project_by_id:
        project = get_project_by_id(args.get_project_by_id)
        if project:
            print(project['name'])
        else:
            print(f"[ERROR] Project '{args.get_project_by_id}' was not found")

# [### --get-project-groups-by-id ###]
    if args.get_project_groups_by_id:
        groups = get_project_groups_by_id(args.get_project_groups_by_id)
        if groups == 0:
            print(f"[ERROR] Project '{args.get_project_groups_by_id}' was found BUT no groups are associated")
        elif groups:
            print(f"{groups}")
        else:
            print(f"[ERROR] Project '{args.get_project_groups_by_id}' was not found")


# [### --get-project-groups-by-name ###]
    if args.get_project_groups_by_name:
        groups = get_project_groups_by_name(args.get_project_groups_by_name)
        if groups == 0:
            print(f"[ERROR] Project '{args.get_project_groups_by_name}' was found BUT no groups are associated")
        elif groups:
            print(f"{groups}")
        else:
            print(f"[ERROR] Project '{args.get_project_groups_by_name}' was not found")

# [### --get-applications ###]
    if args.get_applications:
        applications = get_applications()
        if applications:
            for application in applications:
                progress = get_application_progress_sast_by_name(application['name'])
                print(f"{application['id']} - {application['name']} - {progress}")
            print(f"[DONE] Existing applications : {len(applications)}")
        else:
            print("[ERROR] No applications was found")

# [### --get-application-by-name ###]
    if args.get_application_by_name:
        application = get_application_by_name(args.get_application_by_name)
        if application:
            print(application['id'])
        else:
            print(f"[ERROR] Application was not found for name {args.get_application_by_name}")

# [### --get-application-by-id ###]
    if args.get_application_by_id:
        application = get_application_by_id(args.get_application_by_id)
        if application:
            print(application['name'])
        else:
            print(f"[ERROR] Application was not found for id {args.get_application_by_id}")

# [### --get-application-projects-by-name ###]
    if args.get_application_projects_by_name:

        # Start spinner
        stop_spinner = threading.Event()
        spinner_thread = threading.Thread(target=spinner, args=(stop_spinner,))
        spinner_thread.start()

        # Run the long-running task
        projects = get_application_projects_by_name(args.get_application_projects_by_name)
       
       # Stop spinner
        stop_spinner.set()
        spinner_thread.join()
        sys.stdout.write('\r')
        sys.stdout.flush()

        if projects == 0:
            print(f"[ERROR] Application '{args.get_application_projects_by_name}' was found BUT NO projects are associated")
        elif projects:
            for project in projects:
                print(f"{project['id']} - {project['name']}")
            print(f"[DONE] Projects associated to application '{args.get_application_projects_by_name}' : {len(projects)}")
        else:
            print(f"[ERROR] Application '{args.get_application_projects_by_name}' was not found")

# [### --get-application-projects-by-id ###]
    if args.get_application_projects_by_id:

        # Start spinner
        stop_spinner = threading.Event()
        spinner_thread = threading.Thread(target=spinner, args=(stop_spinner,))
        spinner_thread.start()

        # Run the long-running task
        projects = get_application_projects_by_id(args.get_application_projects_by_id)
       
       # Stop spinner
        stop_spinner.set()
        spinner_thread.join()
        sys.stdout.write('\r')
        sys.stdout.flush()

        if projects == 0:
            print(f"[ERROR] Application '{args.get_application_projects_by_id}' was found BUT NO projects are associated")
        elif projects:
            for project in projects:
                print(f"{project['id']} - {project['name']}")
            print(f"[DONE] Projects associated to application '{args.get_application_projects_by_id}' : {len(projects)}")
        else:
            print(f"[ERROR] Application '{args.get_application_projects_by_id}' was not found")

# [### --update-project-group-by-name ###]
    if args.update_project_group_by_id and args.project_id:
        project = update_project_group_by_id(args.project_id, args.update_project_group_by_id)
        if project == 0:
            print(f"[ERROR] Project '{args.project_id}' was found BUT NOT possible to add the group id {args.update_project_group_by_id}")
        elif project:
            print(f"[DONE] Successful update now the project '{args.project_id}' its associated with groups '{project['groups']}'")
        else:
            print(f"[ERROR] Project '{args.project_id}' was not found")

# [### --get-application-progress-sast-by-name ###]
    if args.get_application_progress_sast_by_name:
        progress = get_application_progress_sast_by_name(args.get_application_progress_sast_by_name)
        print(progress)
        if progress:
            print(f"[DONE] Application '{args.get_application_progress_sast_by_name}' have a progress of '{progress}'")
        else:
            print(f"[ERROR] Application '{args.get_application_progress_sast_by_name}' was not found")






    if args.create_project:
        new_project = create_project(args.create_project)
        if new_project:
            print(f"Project created: {new_project['id']} - {new_project['name']}")
        else:
            print("Project not created")
    
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

    
    
    



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Interact with Checkmarx AST API")
    parser.add_argument("--get-projects", action="store_true", help="Get projects")
    parser.add_argument("--get-project-by-name", metavar="NAME", help="Get project ID using project name")
    parser.add_argument("--get-project-by-id", metavar="ID", help="Get project NAME using project id")
    parser.add_argument("--get-project-groups-by-name", metavar="NAME", help="Get project groups using NAME")
    parser.add_argument("--get-project-groups-by-id", metavar="ID", help="Get project groups using ID")

    parser.add_argument("--get-applications", action="store_true", help="Get applications")
    parser.add_argument("--get-application-by-name", metavar="NAME", help="Get application ID using application name")
    parser.add_argument("--get-application-by-id", metavar="NAME", help="Get application NAME using application id")
    
    parser.add_argument("--get-application-projects-by-name", metavar="NAME", help="Get groups associated to application using application name")
    parser.add_argument("--get-application-projects-by-id", metavar="ID", help="Get groups associated to application using application id")
    parser.add_argument("--get-application-progress-sast-by-name", metavar="NAME", help="Get progress of application using application name")

    parser.add_argument("--update-project-group-by-id", metavar="GROUP_ID", help="Update a specific project's group (requires --project-id)")

    parser.add_argument("--create-project", metavar="NAME", help="Create a new project")
    parser.add_argument("--upload-file", metavar="FILE", help="Upload a file to the project (requires --project-id)")
    parser.add_argument("--start-scan", action="store_true", help="Start a security scan (requires --project-id)")
    parser.add_argument("--get-scan-results", action="store_true", help="Get scan results (requires --scan-id)")
    
    
    parser.add_argument("--project-id", metavar="ID", help="Project ID for specific operations")
    parser.add_argument("--scan-id", metavar="ID", help="Scan ID to get results")
  
    parser.add_argument("--get-projects-by-application", metavar="NAME", help="Get all projects associated with an application name")
    args = parser.parse_args()
    main(args)
