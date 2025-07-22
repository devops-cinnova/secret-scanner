import os
from rich.console import Console
from rich.table import Table
from scanner.utils import find_secrets_in_line, ALLOWED_EXTENSIONS
from rich.panel import Panel
from rich.text import Text
from rich.markdown import Markdown
from rich import box
import fnmatch

console = Console()

def get_ignore_patterns(base_path):
    ignore_file = os.path.join(base_path, ".secret-scanner-ignore")
    patterns = []
    if os.path.isfile(ignore_file):
        with open(ignore_file, 'r') as f:
            for line in f:
                cleaned = line.strip()
                if cleaned and not cleaned.startswith('#'):
                    patterns.append(cleaned)
    return patterns

def should_ignore_file(file_path, ignore_patterns):
    normalized_path = file_path.replace("\\", "/")
    file_name = os.path.basename(normalized_path)
    for pattern in ignore_patterns:
        pattern = pattern.strip()
        if not pattern:
            continue
        if pattern.endswith("/"):
            if normalized_path.startswith(pattern) or f"/{pattern.strip('/')}/" in normalized_path:
                return True
        if pattern == file_name or pattern == normalized_path:
            return True
        # Glob-style matching (e.g. *.jpg)
        if fnmatch.fnmatch(normalized_path, pattern) or fnmatch.fnmatch(file_name, pattern):
            return True
    return False

def scan_for_secrets(base_path, verbose=False):
    findings = []
    ignore_patterns = get_ignore_patterns(base_path)
    for root, dirs, files in os.walk(base_path):
        for file in files:
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, base_path)
            if should_ignore_file(rel_path, ignore_patterns):
                if verbose:
                    console.print(f"[yellow][SKIP][/yellow] Ignored by pattern: [bold]{rel_path}[/bold]")
                continue

            if not file.lower().endswith(ALLOWED_EXTENSIONS):
                if verbose:
                    console.print(f"[blue][SKIP][/blue] Unsupported file type: [bold]{rel_path}[/bold]")
                continue
            if verbose:
                console.print(f"[cyan][SCAN][/cyan] Scanning file: [bold]{rel_path}[/bold]")
            try:
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for i, line in enumerate(f, start=1):
                        secrets = find_secrets_in_line(line)
                        for secret_type, secret_value in secrets:
                            findings.append({
                                "file": rel_path,
                                "line": i,
                                "risk": secret_type,
                                "secret": secret_value
                            })
            except Exception as e:
                if verbose:
                    console.print(f"[red][ERROR][/red] Could not read file: [bold]{rel_path}[/bold] ([italic]{str(e)}[/italic])")

    return findings

def print_scan_results(findings):
    if not findings:
        console.print("\n[bold green]✅ No secrets found! Your codebase appears clean. 🎉[/bold green]\n")
        return

    console.print("\n[bold red]🚨 Secrets Detected![/bold red]\n")
    for finding in findings:
        file_info = f"[magenta]File:[/magenta] [bold]{finding['file']}[/bold]  [cyan]Line:[/cyan] [bold]{finding['line']}[/bold]"
        risk_info = f"[red]Risk Type:[/red] [bold]{finding['risk']}[/bold]"
        secret_snippet = f"[yellow]Secret:[/yellow] [italic]{finding['secret'][:8]}{'...' if len(finding['secret']) > 8 else ''}[/italic]"
        panel_content = f"{file_info}\n{risk_info}\n{secret_snippet}"
        console.print(Panel(panel_content, title="[bold red]Secret Found[/bold red]", expand=False, border_style="red", box=box.ROUNDED))

    console.print(f"\n[bold red]⚠️  {len(findings)} potential secret(s) detected. Please review immediately![/bold red]\n")