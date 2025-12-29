"""
Output Module
Handles formatting and exporting results.
"""

import json
from rich.console import Console
from rich.table import Table

def output_results(results, format_type, file_path=None):
    """Output results in specified format."""
    if format_type == "terminal":
        console = Console()
        table = Table(title="Network Scan Results")
        table.add_column("Host", style="cyan")
        table.add_column("OS", style="magenta")
        table.add_column("Open Ports", style="green")
        
        for host, data in results.items():
            ports = ", ".join([f"{p}: {b}" for p, b in data.get("open_ports", {}).items()])
            table.add_row(host, data.get("os", "N/A"), ports)
        
        console.print(table)
    
    elif format_type == "json":
        with open(file_path or "results.json", "w") as f:
            json.dump(results, f, indent=4)
        print(f"Results saved to {file_path or 'results.json'}")
    
    elif format_type == "txt":
        with open(file_path or "results.txt", "w") as f:
            for host, data in results.items():
                f.write(f"Host: {host}\n")
                f.write(f"OS: {data.get('os', 'N/A')}\n")
                f.write("Open Ports:\n")
                for port, banner in data.get("open_ports", {}).items():
                    f.write(f"  {port}: {banner}\n")
                f.write("\n")
        print(f"Results saved to {file_path or 'results.txt'}")