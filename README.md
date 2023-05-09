# Checkmarx AST Script

This Python script allows you to interact with the Checkmarx AST API. You can perform operations such as listing projects, creating a new project, uploading a file, starting a security scan, fetching scan results, and updating a project's group.

## Requirements

- Python 3.6 or higher
- Checkmarx AST API key

## Usage

To use the script, run it with the desired command line arguments. The script supports the following options:

- `--get-projects`: Retrieve the list of projects.
- `--create-project NAME`: Create a new project with the given name.
- `--upload-file FILE`: Upload a file to a project. Requires the `--project-id` argument.
- `--start-scan`: Start a security scan for a project. Requires the `--project-id` argument.
- `--get-scan-results`: Get the results of a scan. Requires the `--scan-id` argument.
- `--update-project-group GROUP_ID`: Update a specific project's group. Requires the `--project-id` argument.
- `--project-id ID`: The project ID for specific operations, such as uploading a file, starting a scan, or updating a project's group.
- `--scan-id ID`: The scan ID to get results.
- `--get-project-id NAME`: Get project ID using project name.
- `--get-application-id NAME`: Get application ID using application name.
- `-get-projects-by-application NAME` Get all projects associated with an application name.

## Examples

- Get projects
python checkmarx_ast.py --get-projects

- Create a new project
python checkmarx_ast.py --create-project "NewProject"

- Upload a file to a project
python checkmarx_ast.py --upload-file /path/to/your/file.ext --project-id PROJECT_ID

- Start a security scan for a project
python checkmarx_ast.py --start-scan --project-id PROJECT_ID

- Get scan results
python checkmarx_ast.py --get-scan-results --scan-id SCAN_ID

- Update a project's group
python checkmarx_ast.py --update-project-group NEW_GROUP_ID --project-id PROJECT_ID

- Get an project ID using the project name
python checkmarx_ast.py --get-project-id "Project Name"

- Get an application ID using the application name
python checkmarx_ast.py --get-project-id "Project Name"

- Get all projects associated with an application name
python checkmarx_ast.py --get-projects-by-application "Application Name"

