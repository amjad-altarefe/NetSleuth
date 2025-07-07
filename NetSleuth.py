#!/usr/bin/env python3
import argparse #To process the commands
import json
import os
import threading
from typing import Any, Dict

import pyshark 
from rich.console import Console
from rich.table import Table

console = Console() #obj from rich for color printing.

# Default suspicious ports often used in backdoors or malware
DEFAULT_SUSPICIOUS_PORTS = {23, 4444, 6667, 31337, 12345, 8080}

# MIME (Multipurpose Internet Mail Extensions) type prefixes indicating binary data   (type/subtype like => text/html, application/pdf, application/json...)
DEFAULT_BINARY_MIME_PREFIXES = ("application/", "binary/", "image/")

# File extensions for binary or media files
DEFAULT_BINARY_EXTENSIONS = (
    ".exe", ".dll", ".bin", ".zip", ".rar", ".7z", ".tar", ".gz",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff",
    ".mp4", ".avi", ".mov", ".mkv", ".webm"
)

# Global flag to stop live capture
stop_capture = False

# Check if MIME type is binary
def is_binary_mime(mime: str) -> bool:
    return any(mime.startswith(pref) for pref in DEFAULT_BINARY_MIME_PREFIXES)

# Check if URI has binary file extension
def is_binary_filename(uri: str) -> bool:
    uri_l = uri.lower()
    return any(uri_l.endswith(ext) for ext in DEFAULT_BINARY_EXTENSIONS)

# Analyze an offline PCAP file
def analyse_pcap(path: str, suspicious_ports: set) -> Dict[str, Any]:
    if not os.path.isfile(path):
        raise FileNotFoundError(path)

    console.log(f"[bold cyan]Loading:[/bold cyan] {path}")

    cap = pyshark.FileCapture(
        path,
        include_raw=False,
        override_prefs={
            "tcp.desegment_tcp_streams": "true",
            "http.desegment_body": "true",
        },
    )

    return process_packets(cap, suspicious_ports)

# Analyze packets in real-time from a live interface
def analyse_live(interface: str, suspicious_ports: set):
    console.log(f"[bold cyan]Capturing live packets from:[/bold cyan] {interface}")
    cap = pyshark.LiveCapture(
        interface=interface,
        override_prefs={
            "tcp.desegment_tcp_streams": "true",
            "http.desegment_body": "true",
        }
    )

    # Data collection during live
    http_requests = []
    file_downloads = []
    suspicious_connections = []

    def process_packet(pkt):
        try:
            if "HTTP" in pkt:
                http = pkt["HTTP"]
                if hasattr(http, "request_method"):
                    req_host = getattr(http, "host", "")
                    req_uri = getattr(http, "request_uri", "")
                    req = {
                        "time": str(pkt.sniff_time),
                        "method": http.request_method,
                        "host": req_host,
                        "uri": req_uri,
                        "user_agent": getattr(http, "user_agent", ""),
                        "src_ip": pkt.ip.src if hasattr(pkt, "ip") else "",
                        "dst_ip": pkt.ip.dst if hasattr(pkt, "ip") else "",
                    }
                    http_requests.append(req)
                    console.print(f"[bold blue][ALERT][/bold blue] HTTP Request: {req['method']} {req['host']}{req['uri']} from {req['src_ip']}")

                    if is_binary_filename(req_uri):
                        file_downloads.append({
                            "time": req["time"],
                            "status": "Requested",
                            "mime": "",
                            "disposition": "",
                            "filename": req_uri,
                            "src_ip": req["src_ip"],
                            "dst_ip": req["dst_ip"],
                        })
                        console.print(f"[bold magenta][ALERT][/bold magenta] Possible File Download Request: {req_uri} from {req['src_ip']}")

                elif hasattr(http, "response_code"):
                    mime = getattr(http, "content_type", "")
                    disposition = getattr(http, "content_disposition", "")
                    uri = getattr(http, "request_uri", "") or getattr(http, "file_data_filename", "")
                    content_length = int(getattr(http, "content_length", "0"))

                    if (
                        is_binary_mime(mime) or
                        "attachment" in disposition.lower() or
                        is_binary_filename(uri) or
                        content_length > 100000
                    ):
                        file_downloads.append({
                             "time": str(pkt.sniff_time),
                            "status": http.response_code,
                            "mime": mime,
                            "disposition": disposition,
                            "filename": uri or "[Unknown]",
                            "src_ip": pkt.ip.src if hasattr(pkt, "ip") else "",
                            "dst_ip": pkt.ip.dst if hasattr(pkt, "ip") else "",
                        })
                        console.print(f"[bold magenta][ALERT][/bold magenta] File Download Detected: {uri} ({mime}) Status: {http.response_code} from {pkt.ip.src if hasattr(pkt, 'ip') else ''}")

            if hasattr(pkt, "tcp") and hasattr(pkt.tcp, "srcport") and hasattr(pkt.tcp, "dstport"):
                sport = int(pkt.tcp.srcport)
                dport = int(pkt.tcp.dstport)
                if sport in suspicious_ports or dport in suspicious_ports:
                    suspicious_connections.append({
                        "time": str(pkt.sniff_time),
                        "src_ip": pkt.ip.src if hasattr(pkt, "ip") else "",
                        "dst_ip": pkt.ip.dst if hasattr(pkt, "ip") else "",
                        "sport": sport,
                        "dport": dport,
                        "info": "Port matches suspicious list",
                    })
                    console.print(f"[bold red][ALERT][/bold red] Suspicious Connection: {pkt.ip.src if hasattr(pkt, 'ip') else ''}:{sport} -> {pkt.ip.dst if hasattr(pkt, 'ip') else ''}:{dport}")

        except Exception:
            pass

    # start sniffing packets and process each immediately
    def capture_loop():
        for pkt in cap.sniff_continuously():
            if stop_capture:
                break
            process_packet(pkt)

    thread = threading.Thread(target=capture_loop)
    thread.start()

    console.print("[bold yellow]Press 'q' then Enter to stop live capture[/bold yellow]")
    while True:
        user_input = input()
        if user_input.strip().lower() == 'q':
            global stop_capture
            stop_capture = True
            break

    thread.join()
    cap.close()

    # After finishing, print a final report.
    report = {
        "summary": {
            "http_requests": len(http_requests),
            "file_downloads": len(file_downloads),
            "suspicious_connections": len(suspicious_connections),
        },
        "http_requests": http_requests,
        "file_downloads": file_downloads,
        "suspicious_connections": suspicious_connections,
    }
    print_report(report)
    
    # Ask the user if he wants to save the report.
    save = input("Do you want to save the summary report as text? (y/n): ").strip().lower()
    if save == "y":
        path = input("Enter output filename (e.g., report.json): ").strip()
        if not path.endswith(".json"):
            path += ".json"
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            console.log(f"[bold green]JSON report saved:[/bold green] {path}")
        except Exception as e:
            console.log(f"[bold red]Failed to save report:[/bold red] {e}")


# Process a list of packets and extract features of interest
def process_packets(packets, suspicious_ports: set) -> Dict[str, Any]:
    http_requests = []
    file_downloads = []
    suspicious_connections = []

    for pkt in packets:
        try:
            # HTTP-related processing
            if "HTTP" in pkt:
                http = pkt["HTTP"]
                if hasattr(http, "request_method"):
                    req_host = getattr(http, "host", "")
                    req_uri = getattr(http, "request_uri", "")
                    req = {
                        "time": str(pkt.sniff_time),
                        "method": http.request_method,
                        "host": req_host,
                        "uri": req_uri,
                        "user_agent": getattr(http, "user_agent", ""),
                        "src_ip": pkt.ip.src if hasattr(pkt, "ip") else "",
                        "dst_ip": pkt.ip.dst if hasattr(pkt, "ip") else "",
                    }
                    http_requests.append(req)

                    # Detect binary downloads by URI
                    if is_binary_filename(req_uri):
                        file_downloads.append({
                            "time": req["time"],
                            "status": "Requested",
                            "mime": "",
                            "disposition": "",
                            "filename": req_uri,
                            "src_ip": req["src_ip"],
                            "dst_ip": req["dst_ip"],
                        })

                elif hasattr(http, "response_code"):
                    mime = getattr(http, "content_type", "")
                    disposition = getattr(http, "content_disposition", "")
                    uri = getattr(http, "request_uri", "") or getattr(http, "file_data_filename", "")
                    if is_binary_mime(mime) or "attachment" in disposition.lower() or is_binary_filename(uri):
                        file_downloads.append({
                            "time": str(pkt.sniff_time),
                            "status": http.response_code,
                            "mime": mime,
                            "disposition": disposition,
                            "filename": uri or "[Unknown]",
                            "src_ip": pkt.ip.src if hasattr(pkt, "ip") else "",
                            "dst_ip": pkt.ip.dst if hasattr(pkt, "ip") else "",
                        })

            # TCP port analysis
            if hasattr(pkt, "tcp") and hasattr(pkt.tcp, "srcport") and hasattr(pkt.tcp, "dstport"):
                sport = int(pkt.tcp.srcport)
                dport = int(pkt.tcp.dstport)
                if sport in suspicious_ports or dport in suspicious_ports:
                    suspicious_connections.append({
                        "time": str(pkt.sniff_time),
                        "src_ip": pkt.ip.src if hasattr(pkt, "ip") else "",
                        "dst_ip": pkt.ip.dst if hasattr(pkt, "ip") else "",
                        "sport": sport,
                        "dport": dport,
                        "info": "Port matches suspicious list",
                    })
        except Exception:
            continue

    return {
        "summary": {
            "http_requests": len(http_requests),
            "file_downloads": len(file_downloads),
            "suspicious_connections": len(suspicious_connections),
        },
        "http_requests": http_requests,
        "file_downloads": file_downloads,
        "suspicious_connections": suspicious_connections,
    }

# Print a summary report using tables
def print_report(report: Dict[str, Any]):
    if report["summary"]["http_requests"] == 0 and report["summary"]["file_downloads"] == 0 and report["summary"]["suspicious_connections"] == 0:
        return

    console.rule("[bold green]Analysis Summary")
    for k, v in report["summary"].items():
        console.print(f"{k.replace('_', ' ').title()}: [bold]{v}[/bold]")

    if report["http_requests"]:
        table = Table(title="HTTP Requests (first 20)")
        table.add_column("Time", style="dim")
        table.add_column("Method")
        table.add_column("Host")
        table.add_column("URI")
        for req in report["http_requests"][:20]:
            full_url = f"http://{req['host']}{req['uri']}" if req["host"] and req["uri"] else req["uri"] or req["host"]
            table.add_row(req["time"], req["method"], req["src_ip"], full_url)
        console.print(table)

    if report["file_downloads"]:
        table = Table(title="File Downloads")
        table.add_column("Time", style="dim")
        table.add_column("Filename")
        table.add_column("Mime")
        table.add_column("Disposition")
        for dl in report["file_downloads"]:
            table.add_row(dl["time"], dl["filename"], dl["mime"], dl["disposition"])
        console.print(table)

    if report["suspicious_connections"]:
        table = Table(title="Suspicious Connections")
        table.add_column("Time", style="dim")
        table.add_column("Src IP")
        table.add_column("Dst IP")
        table.add_column("Sport")
        table.add_column("Dport")
        table.add_column("Reason")
        for sc in report["suspicious_connections"]:
            table.add_row(
                sc["time"],
                sc["src_ip"],
                sc["dst_ip"],
                str(sc["sport"]),
                str(sc["dport"]),
                sc["info"],
            )
        console.print(table)

# Command-line interface and script entry point
def main():
    parser = argparse.ArgumentParser(description="Network Analyzer – PCAP or Live HTTP & Port Monitor")
    parser.add_argument("-i", "--input", help="Input .pcap or .pcapng file")
    parser.add_argument("-l", "--live", metavar="INTERFACE", help="Enable live capture on specified interface")
    parser.add_argument("-o", "--output", help="Optional JSON report output path")
    parser.add_argument(
        "--suspicious-ports",
        nargs="*",
        type=int,
        default=list(DEFAULT_SUSPICIOUS_PORTS),
        help="List of TCP ports considered suspicious",
    )
    args = parser.parse_args()

    if args.live:
        analyse_live(args.live, set(args.suspicious_ports))
    elif args.input:
        report = analyse_pcap(args.input, set(args.suspicious_ports))
        print_report(report)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            console.log(f"[bold green]JSON report saved:[/bold green] {args.output}")
    else:
        parser.error("Either --input or --live with --interface is required")

if __name__ == "__main__":
    main()
