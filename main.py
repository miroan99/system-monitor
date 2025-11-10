"""
System Security Monitor
Monitors network connections, running processes, and startup programs
"""

import psutil
import socket
import datetime
import platform
from collections import defaultdict


def get_system_info():
    """Display basic system information"""
    print("=" * 60)
    print("SYSTEM INFORMATION")
    print("=" * 60)
    print(f"System: {platform.system()} {platform.release()}")
    print(f"Machine: {platform.machine()}")
    print(f"Processor: {platform.processor()}")
    print(f"Scan Time: {datetime.datetime.now()}")
    print()


def monitor_network_connections():
    """Monitor active network connections"""
    print("=" * 60)
    print("ACTIVE NETWORK CONNECTIONS")
    print("=" * 60)

    connections = psutil.net_connections(kind='inet')
    connection_data = []

    for conn in connections:
        if conn.status == 'ESTABLISHED':
            try:
                process = psutil.Process(conn.pid) if conn.pid else None
                process_name = process.name() if process else "Unknown"

                local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"

                connection_data.append({
                    'process': process_name,
                    'pid': conn.pid,
                    'local': local_addr,
                    'remote': remote_addr,
                    'status': conn.status
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    # Group by process
    process_connections = defaultdict(list)
    for conn in connection_data:
        process_connections[conn['process']].append(conn)

    for process_name, conns in sorted(process_connections.items()):
        print(f"\n[{process_name}] (PID: {conns[0]['pid']})")
        for conn in conns[:5]:  # Show first 5 connections per process
            print(f"  Local: {conn['local']} -> Remote: {conn['remote']}")
        if len(conns) > 5:
            print(f"  ... and {len(conns) - 5} more connections")

    print(f"\nTotal active connections: {len(connection_data)}")
    print()


def check_suspicious_processes():
    """Check for potentially suspicious running processes"""
    print("=" * 60)
    print("RUNNING PROCESSES ANALYSIS")
    print("=" * 60)

    suspicious_keywords = ['miner', 'crypto', 'hack', 'keylog', 'trojan', 'rat', 'backdoor']
    high_network_processes = []
    suspicious_processes = []

    for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
        try:
            pinfo = proc.info

            # Check for suspicious names
            proc_name_lower = pinfo['name'].lower()
            if any(keyword in proc_name_lower for keyword in suspicious_keywords):
                suspicious_processes.append(pinfo)

            # Check network usage
            try:
                net_io = proc.io_counters()
                if net_io.read_bytes > 10_000_000 or net_io.write_bytes > 10_000_000:  # >10MB
                    high_network_processes.append({
                        'name': pinfo['name'],
                        'pid': pinfo['pid'],
                        'read_mb': net_io.read_bytes / 1_000_000,
                        'write_mb': net_io.write_bytes / 1_000_000
                    })
            except (psutil.AccessDenied, AttributeError):
                pass

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if suspicious_processes:
        print("\n⚠️  SUSPICIOUS PROCESS NAMES DETECTED:")
        for proc in suspicious_processes:
            print(f"  - {proc['name']} (PID: {proc['pid']}, User: {proc['username']})")
    else:
        print("\n✓ No obviously suspicious process names detected")

    if high_network_processes:
        print("\n📊 HIGH NETWORK USAGE PROCESSES:")
        for proc in sorted(high_network_processes, key=lambda x: x['read_mb'] + x['write_mb'], reverse=True)[:10]:
            print(f"  - {proc['name']} (PID: {proc['pid']})")
            print(f"    Read: {proc['read_mb']:.2f} MB, Write: {proc['write_mb']:.2f} MB")

    print()


def check_listening_ports():
    """Check for programs listening on network ports"""
    print("=" * 60)
    print("LISTENING PORTS (Programs waiting for connections)")
    print("=" * 60)

    listening = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'LISTEN':
            try:
                process = psutil.Process(conn.pid) if conn.pid else None
                process_name = process.name() if process else "Unknown"

                listening.append({
                    'process': process_name,
                    'pid': conn.pid,
                    'port': conn.laddr.port,
                    'address': conn.laddr.ip
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    for item in sorted(listening, key=lambda x: x['port']):
        print(f"Port {item['port']:5d} - {item['process']} (PID: {item['pid']}) on {item['address']}")

    print(f"\nTotal listening ports: {len(listening)}")
    print()


def get_network_stats():
    """Display network interface statistics"""
    print("=" * 60)
    print("NETWORK STATISTICS")
    print("=" * 60)

    net_io = psutil.net_io_counters()
    print(f"Bytes Sent:     {net_io.bytes_sent / 1_000_000:.2f} MB")
    print(f"Bytes Received: {net_io.bytes_recv / 1_000_000:.2f} MB")
    print(f"Packets Sent:   {net_io.packets_sent}")
    print(f"Packets Recv:   {net_io.packets_recv}")
    print(f"Errors In:      {net_io.errin}")
    print(f"Errors Out:     {net_io.errout}")
    print()


def main():
    """Main monitoring function"""
    print("\n🔍 SYSTEM SECURITY MONITOR\n")

    try:
        get_system_info()
        get_network_stats()
        monitor_network_connections()
        check_listening_ports()
        check_suspicious_processes()

        print("=" * 60)
        print("RECOMMENDATIONS:")
        print("=" * 60)
        print("1. Review any suspicious process names or unfamiliar programs")
        print("2. Check listening ports - ensure you recognize all services")
        print("3. Investigate any unexpected high network usage")
        print("4. Use Task Manager to see startup programs (Ctrl+Shift+Esc)")
        print("5. Run a full antivirus/malware scan with updated definitions")
        print("6. Check Windows Firewall settings and rules")
        print("\n⚠️  NOTE: This script requires administrator privileges for")
        print("   complete process information. Run as admin for best results.")
        print("=" * 60)

    except Exception as e:
        print(f"\n❌ Error during monitoring: {e}")
        print("Try running this script as administrator for full access.")


if __name__ == "__main__":
    main()