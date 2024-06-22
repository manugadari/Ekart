import os
import subprocess
import json
import argparse
import logging
from git import Repo
import sys
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] - %(message)s')
logger = logging.getLogger(__name__)

class SnykScanner: 
    
    @staticmethod
    def check_snyk_installed():
        """
        Check if Snyk CLI is installed.
        """
        try:
            logger.info("----------------check_snyk_installed started-----------------")
            result = subprocess.run(['snyk', '--version'], capture_output=True, text=True)
            result.check_returncode()
            logger.info(f"Snyk CLI is installed: {result.stdout.strip()}")
            logger.info("----------------check_snyk_installed Ended-----------------")
        except subprocess.CalledProcessError:
            logger.error("Snyk CLI is not installed. Please install it from https://snyk.io/docs/snyk-cli-installation/")
            logger.info("----------------check_snyk_installed Ended-----------------")
            raise

    @staticmethod
    def check_snyk_token(token):
        """
        Check auth token from environment variable.
        """
        try:
            logger.info("----------------check_snyk_token Started-----------------")
            if 'SNYK_TOKEN' in os.environ:
                logger.error("SNYK_TOKEN environment variable not set.")
                raise ValueError("SNYK_TOKEN environment variable not set.")
            subprocess.run(['snyk', 'auth', token], check=True)
            logger.info("Authenticated to Snyk successfully.")
            logger.info("----------------check_snyk_token Ended-----------------")
        except subprocess.CalledProcessError as e:
             logger.error(f"Failed to authenticate to Snyk: {e}")
             logger.info("----------------check_snyk_token Ended-----------------")
             raise

    def trigger_sca_scan(self, target, project_name=None, target_name=None):
        """
        Trigger SAST scan using Snyk CLI.
        :param target: Path to the project or list of changed files to be scanned.
        :param output_file: Path to save the JSON file output.
        :return: Scan results in JSON format.
        """
        try:
            logger.info("----------------trigger_sca_scan Started-----------------")
            if isinstance(target, str):
                # Scan the entire project
                command = ['snyk', 'test','--json', target]
            elif isinstance(target, list):
                flag_changed_files = [f"--file={file}" for file in target]
                command = ['snyk', 'test', '--json'] + flag_changed_files
            if project_name!=None:
                command.append(f"--report")
                command.append(f"--project-name={project_name}")
                if target_name!=None:
                    command.append(f"--target-name={target_name}")  
            # else:
                # raise ValueError("Invalid target for scan. Must be a string (project path) or list (changed files).")
            logger.info(f"Running Command - {command}")

            result = subprocess.run(command, capture_output=True, text=True)
            #logger.info(f" result:{result}")

            if result.returncode == 0:
                logger.info("CLI scan completed successfully. No vulnerabilities found.")
            elif result.returncode == 1:
                logger.warning("CLI scan completed. Vulnerabilities found.")
            elif result.returncode == 2:
                logger.error("CLI scan failed. Failure, try to re-run the command.")
            elif result.returncode == 3:
                logger.error("CLI scan failed. No supported projects detected.")
            else:
                logger.error(f"CLI scan failed with unexpected error code: {result.returncode}")
            scan_results = json.loads(result.stdout)
            logger.info("----------------trigger_sca_scan Ended-----------------")
            return scan_results
        except subprocess.CalledProcessError as e:
            logger.error(f"Error running Snyk CLI: {e}")
            logger.info("----------------trigger_sca_scan Ended-----------------")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing JSON output: {e}")
            logger.info("----------------trigger_sca_scan Ended-----------------")
            raise

    def get_changed_files(self, repo_path, base_branch, pr_branch):
        """
        Get the list of changed files between the base branch and PR branch using GitPython.
        :param repo_path: Path to the Git repository.
        :param base_branch: The base branch of the PR.
        :param pr_branch: The PR branch.
        :return: List of changed files.
        """
        try:
            
            logger.info("----------------get_changed_files Started-----------------")
            repo = Repo(repo_path)
            # Fetch the latest changes from the remote repository
            origin = repo.remotes.origin
            origin.fetch()
            
            # Get the commit hashes for the branch heads
            base_commit = origin.refs[base_branch].commit
            compare_commit = origin.refs[pr_branch].commit
            
            # Perform the diff between the branches
            diff_index = base_commit.diff(compare_commit)
            changed_files = [item.a_path for item in diff_index]
            logger.info(f"Found {len(changed_files)} changed files between {base_branch} and {pr_branch}.")
            logger.info(f"Changed Files: {changed_files}")
            logger.info("----------------get_changed_files Ended----------------")
            return changed_files
        except Exception as e:
            logger.error(f"Error getting changed files: {e}")
            logger.info("----------------get_changed_files Ended----------------")
            raise
        
    @staticmethod
    def summarize_severities(scan_results):
        """
        Summarize the severities of issues found in the scan results.
        :param scan_results: Scan results in JSON format.
        :return: Dictionary summarizing severities.
        """
        severity_counts = {'low': 0, 'medium': 0, 'high': 0}
        try:
            logger.info("----------------summarize_severities Started-----------------")
            for run in scan_results.get('runs', []):
                for result in run.get('results', []):
                    level = result.get("level", "")
                    if level in ['note', 'info'] :
                        severity_counts["low"] += 1
                    elif level == 'warning':
                        severity_counts["medium"] += 1
                    else:
                        severity_counts["high"] += 1
            logger.info(f"Severity summary: {severity_counts}")
            severity_counts['scan_time'] = scan_results.get('scan_time', 0)  # Include scan time in summary
            logger.info("----------------summarize_severities Ended-----------------")
            return severity_counts
        except Exception as e:
            logger.error(f"Error summarizing severities: {e}")
            logger.info("----------------summarize_severities Ended-----------------")
            raise

    @staticmethod
    def save_results_to_json(results, file_path):
        """
        Save scan results to a JSON file.
        :param results: Scan results in JSON format.
        :param file_path: Path to save the JSON file.
        """
        try:
            logger.info("----------------save_results_to_json Started-----------------")
            with open(file_path, 'w') as f:
                json.dump(results, f, indent=4)
            logger.info(f"Scan results saved to {file_path}.")
            logger.info("----------------save_results_to_json Ended-----------------")
        except Exception as e:
            logger.error(f"Error saving scan results to {file_path}: {e}")
            logger.info("----------------save_results_to_json Ended-----------------")
            raise

    @staticmethod
    def convert_json_to_html(json_file, html_file):
        """
        Convert JSON scan results to HTML using snyk-to-html.
        :param json_file: Path to the JSON file.
        :param html_file: Path to save the HTML file.
        """
        try:
            logger.info("----------------convert_json_to_html Started-----------------")
            logger.info(f"JSON File PATH: {json_file}")
            logger.info(f"HTML File PATH: {html_file}")
            result = subprocess.run(['snyk-to-html', '-i', json_file, '-a'], capture_output=True, text=True)
            if result.returncode == 0:
                print("Command executed successfully.")
                #print("Output HTML content:")
                #print(result.stdout)  # Print the captured standard output (HTML content)
            else:
                print("Command failed with return code:", result.returncode)
                print("Error output:")
                print(result.stderr) 
            result.check_returncode()
            logger.info(f"Converted JSON results to HTML file at {html_file}")
            logger.info("----------------convert_json_to_html Ended-----------------")
        except subprocess.CalledProcessError as e:
            logger.error(f"Error converting JSON to HTML: {e}")
            logger.info("----------------convert_json_to_html Ended-----------------")
            raise
    
    @staticmethod
    def evaluate_severity_summary(severity_summary):
        """
        Evaluate severity summary and determine pipeline result.
        :param severity_summary: Severity summary dictionary.
        :return: Boolean indicating whether pipeline should pass or fail.
        """
        logger.info("----------------evaluate_severity_summary Started-----------------")
        if severity_summary.get('high', 0) > 0:
            logger.error("High severity issues found. Pipeline will fail.")
            logger.info("----------------evaluate_severity_summary Ended-----------------")
            return False
        else:
            logger.info("No high severity issues found. Pipeline will pass.")
            logger.info("----------------evaluate_severity_summary Ended-----------------")
            return True

def load_config(config_file):
    """
    Load configuration from a JSON file.
    :param config_file: Path to the configuration file.
    :return: Configuration dictionary.
    """
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        logger.info(f"Configuration loaded from {config_file}.")
        return config
    except Exception as e:
        logger.error(f"Error loading configuration from {config_file}: {e}")
        raise

def main():
    logger.info("----------------Main started-----------------")  
    if not os.path.exists("outputs"):
        os.mkdir("outputs")
    scan_summary_file_path = './outputs/sca_severity_summary.json'
    scan_json_file_path = "./outputs/sca_scan_results.json"
    scan_html_file_path = "./outputs/sca_scan_results.html"
    
    parser = argparse.ArgumentParser(description="Snyk SAST Scanner")
    parser.add_argument('--scan-for-push', action='store_true', help="Trigger SAST scan using Snyk CLI")
    parser.add_argument('--scan-for-pr', action='store_true', help="Trigger SAST scan on changed files in a PR branch")
    parser.add_argument('--report', action='store_true', help="Upload results to Snyk Web UI")
    parser.add_argument('--target-name', help="Upload results to Snyk Web UI")
    parser.add_argument('--base-branch', help="Base branch of the PR")
    parser.add_argument('--pr-branch', help="PR branch")
    parser.add_argument('--repo-path', default="./", help="Path to the Git repository")

    args = parser.parse_args()
    logger.info(f"Arguments: {args}")
    config = load_config("config.json") # file path

    project_path = config.get('project_path')
    org_id = config.get('org_id')
    project_id = config.get('project_id')
    token = config.get('auth_token')
    target=config.get('target')

    # Check if Snyk CLI is installed
    try:
        SnykScanner.check_snyk_installed()
    except Exception as e:
        logger.error(f"Snyk CLI check failed: {e}")
        return
    
    #Authenticate to Snyk
    try:
        SnykScanner.check_snyk_token(token)
    except ValueError as e:
        logger.error(f"Authentication failed: {e}")
        return

    scanner = SnykScanner()
    execution_time = 0
    if args.scan_for_push:
        if not args.report:
            start_time = time.time()
            scan_results = scanner.trigger_sca_scan(target)
            end_time = time.time()
            execution_time = end_time - start_time
            logger.info(f"Snyk scan execution time: {execution_time:.2f} seconds")
        else:
            start_time = time.time()
            scan_results= scanner.trigger_sca_scan(project_name=project_path) #, target_name=target_name)  
            end_time = time.time()
            execution_time = end_time - start_time
            logger.info(f"Snyk scan execution time: {execution_time:.2f} seconds") 
        if scan_results:
            severity_summary = scanner.summarize_severities(scan_results)
            scan_summary = {"execution_time": execution_time, "summary": severity_summary}
            scanner.save_results_to_json(scan_results, scan_json_file_path)
            scanner.convert_json_to_html(scan_json_file_path, scan_html_file_path)
            scanner.save_results_to_json(scan_summary, scan_summary_file_path)
            if not scanner.evaluate_severity_summary(severity_summary):
                sys.exit(1)  # Fail pipeline

    if args.scan_for_pr:
        if not args.repo_path or not args.base_branch or not args.pr_branch:
            logger.error("Base branch and PR branch are required for scanning a Pull Request.")
            sys.exit(1)
        changed_files = scanner.get_changed_files(args.repo_path, args.base_branch, args.pr_branch)
        #logger.info(f"Changed Files {changed_files}")
        logger.info(f"Count of changed files: {len(changed_files)}")
        if changed_files:
            start_time = time.time()
            scan_results = scanner.trigger_sca_scan(changed_files)
            end_time = time.time()
            execution_time = end_time - start_time
            logger.info(f"Snyk scan execution time: {execution_time:.2f} seconds") 
        if scan_results:
            severity_summary = scanner.summarize_severities(scan_results)
            scan_summary = {"execution_time": execution_time, "summary": severity_summary}
            scanner.save_results_to_json(scan_results, scan_json_file_path)
            scanner.convert_json_to_html(scan_json_file_path, scan_html_file_path)
            scanner.save_results_to_json(scan_summary, scan_summary_file_path)
            if not scanner.evaluate_severity_summary(severity_summary):
                sys.exit(1)  # Fail pipeline
            else:
                logger.info("No changed files found to scan")

    logger.info("----------------Main Ended-----------------")   
if __name__ == "__main__":
    main()
