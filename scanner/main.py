import argparse
import os
from scanner.scanner import scan_for_secrets, print_scan_results


def main():
    # Set up the command-line argument parser for the Secret-Scanner tool
    parser = argparse.ArgumentParser(
        description="Secret-Scanner – Advanced Secrets Detection Tool for DevOps and Security Teams"
    )

    # Add an optional path argument (defaults to current directory)
    parser.add_argument(
        "--path",
        type=str,
        default=".",
        help="Path to the directory or repository you want to scan (default: current directory)"
    )

    # Add a verbose flag for extra output
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed scanning progress and skipped files"
    )

    # Parse arguments from the command line
    args = parser.parse_args()

    # Validate that the provided path exists
    if not os.path.exists(args.path):
        print(f"[ERROR] The specified path '{args.path}' does not exist. Please check the path and try again.")
        exit(1)

    # Validate that the provided path is a directory
    if not os.path.isdir(args.path):
        print(f"[ERROR] The specified path '{args.path}' is not a directory. Please provide a valid directory path.")
        exit(1)

    try:
        print(f"[INFO] Starting secret scan in: {os.path.abspath(args.path)}\n")
        # Run the secret scan and collect results
        findings = scan_for_secrets(args.path, args.verbose)

        # Display the scan results in a formatted table
        print_scan_results(findings)

        print("\n[INFO] Secret scan completed.")

    except Exception as e:
        print(f"[FATAL] An unexpected error occurred: {str(e)}\nPlease report this issue if it persists.")
        exit(1)

# Entry point for the CLI tool
if __name__ == "__main__":
    main()