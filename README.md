# Checkmarx AST Script

This Python script allows you to interact with the Checkmarx AST API. You can perform operations such as listing projects, creating a new project, uploading a file, starting a security scan, fetching scan results, and updating a project's group.

## Requirements

- Python 3.6 or higher
- Checkmarx AST API key

## Usage

To use the script, run it with the desired command line arguments. The script supports the following options:

- `--get-projects`: Retrieve the list of projects.
- `--get-project-by-name NAME`: Get project ID using project name.
- `--get-project-by-id ID`: Get project NAME using project id.
- `--get-project-groups-by-name NAME`: Retrieve the list of groups associated to project using name.
- `--get-project-groups-by-name ID`: Retrieve the list of groups associated to project using id.

- `--get-applications`: Retrieve the list of applications.
- `--get-application-by-name NAME`: Get application ID using application name.
- `--get-application-by-id ID`: Get application NAME using application id.
- `--get-application-projects-by-name NAME` Get all projects associated with an application name.
- `--get-application-projects-by-id ID` Get all projects associated with an application id.

- `--create-project NAME`: Create a new project with the given name.
- `--upload-file FILE`: Upload a file to a project. Requires the `--project-id` argument.
- `--start-scan`: Start a security scan for a project. Requires the `--project-id` argument.
- `--get-scan-results`: Get the results of a scan. Requires the `--scan-id` argument.
- `--update-project-group GROUP_ID`: Update a specific project's group. Requires the `--project-id` argument.
- `--project-id ID`: The project ID for specific operations, such as uploading a file, starting a scan, or updating a project's group.
- `--scan-id ID`: The scan ID to get results.

## Examples

- Get projects (TESTED)
`python checkmarx_ast.py --get-projects`

- Get project ID using project NAME (TESTED)
`python checkmarx_ast.py --get-project-by-name NAME`

- Get project NAME using project ID (TESTED)
`python checkmarx_ast.py --get-project-by-id ID`

- Get groups project using project NAME (TESTED)
`python checkmarx_ast.py --get-project-groups-by-name NAME`

- Get groups project using project ID (TESTED)
`python checkmarx_ast.py --get-project-groups-by-id ID`



- Get applications (TESTED)
`python checkmarx_ast.py --get-applications`

- Get application ID using application NAME (TESTED)
`python checkmarx_ast.py --get-application-by-name "NAME"`

- Get application NAME using application ID (TESTED)
`python checkmarx_ast.py --get-application-by-id "ID"`

- Get application projects using application NAME (TESTED)
`python checkmarx_ast.py --get-application-projects-by-name "NAME"`

- Get application projects using application ID (TESTED)
`python checkmarx_ast.py --get-application-projects-by-id "ID"`



- Create a new project (TESTED)
`python checkmarx_ast.py --create-project "NewProject"`

- Upload a file to a project
`python checkmarx_ast.py --upload-file /path/to/your/file.ext --project-id PROJECT_ID`

- Start a security scan for a project
`python checkmarx_ast.py --start-scan --project-id PROJECT_ID`

- Get scan results
`python checkmarx_ast.py --get-scan-results --scan-id SCAN_ID`





- Get all projects associated with an application name
`python checkmarx_ast.py --get-projects-by-application "Application Name"`

