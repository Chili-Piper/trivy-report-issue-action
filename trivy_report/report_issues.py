#!/usr/bin/env python
import argparse
import json
import os
import subprocess
import sys

from trivy_report.parser import parse_issues_json_string
from trivy_report.report_generator import ReportDict, generate_issues, parse_results


def abort(text: str):
    """
    Aborts the execution by printing an error message to stderr and exiting with error code 1
    """
    print(text, file=sys.stderr)
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Parses Trivy JSON report files and reports new vulnerabilities as GitHub issues. "
            "Existing issues are read from the repository $GITHUB_REPOSITORY and used to exclude reported issues."
        )
    )
    parser.add_argument("file")
    args = parser.parse_args()

    filename = args.file

    data: ReportDict = json.load(open(filename, "rb"))
    if not isinstance(data, dict):
        abort(f"Data in json file {filename} does not contain a dictionary")
    github_event = os.environ.get("GITHUB_EVENT_NAME")
    github_repo = os.environ.get("GITHUB_REPOSITORY")
    github_token = os.environ.get("GITHUB_TOKEN")
    input_label = os.environ.get("INPUT_LABEL")
    assignee = os.environ.get("INPUT_ASSIGNEE")
    extra_args = []
    if assignee:
        extra_args.extend(["--assignee", assignee])
    if not github_repo:
        abort("Env variable GITHUB_REPOSITORY must be set")
    if not input_label:
        abort("Env variable INPUT_LABEL must be set")

    print("GitHub Token: " + ("***" if github_token else "<empty>"))
    print(
        f'Executing: gh --repo "{github_repo}" issue list --label "{input_label}" --json title --jq .'
    )
    proc = subprocess.Popen(
        [
            "gh",
            "--repo",
            github_repo,
            "issue",
            "list",
            "--label",
            input_label,
            "--json",
            "title",
            "--jq",
            ".",
        ],
        stdout=subprocess.PIPE,
    )
    stdout, stderr = proc.communicate()
    if proc.returncode != 0 or not stdout:
        abort("Failed to fetch issue list with `gh` cli")
    try:
        existing_issues = parse_issues_json_string(stdout)
    except TypeError as e:
        abort(f"Failed to parse GitHub issue JSON: {e}")

    try:
        reports = parse_results(data, existing_issues=existing_issues)
    except TypeError as e:
        abort(f"Failed to parse Trivy JSON report: {e}")
    except KeyError as e:
        print(f"No results from scan. Error: {e}")
        sys.exit(0)

    issues = generate_issues(reports)
    comment_content = ''

    if github_event == 'pull_request':
        # Generate PR Comment
        pr_number = os.environ.get("GITHUB_REF")
        pr_number = pr_number.split('/')[2]
        print(f"Creating GitHub PR Comments for {github_repo} pull request {pr_number}")
        print(
            f'gh --repo "{github_repo}" pr comment {pr_number}" --body ... " '
            + " ".join(extra_args)
        )
        if issues:
            for issue in issues:
                comment_content = comment_content + issue.body + "<br>"
            if comment_content != '':
                proc = subprocess.Popen(
                    [
                        "gh",
                        "--repo",
                        github_repo,
                        "pr",
                        "comment",
                        pr_number,
                        "--body",
                        comment_content,
                    ]
                    + extra_args
                )
                proc.communicate()
                if proc.returncode != 0:
                    abort("Failed to create comment with `gh` cli")
    else:
        # Generate issues
        for issue in issues:
            comment_content = comment_content + issue.body + "<br>"
            print(f"Creating GitHub issue `{issue.title}`")
            print(
                f'gh --repo "{github_repo}" issue create --title "{issue.title}" --body ... --label "{input_label}" '
                + " ".join(extra_args)
            )
            proc = subprocess.Popen(
                [
                    "gh",
                    "--repo",
                    github_repo,
                    "issue",
                    "create",
                    "--title",
                    issue.title,
                    "--body",
                    issue.body,
                    "--label",
                    input_label,
                ]
                + extra_args
            )
            proc.communicate()
            if proc.returncode != 0:
                abort("Failed to create issue with `gh` cli")
        else:
            print("No new vulnerabilities found")


if __name__ == "__main__":
    main()
