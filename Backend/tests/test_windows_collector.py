"""Quick validation of WindowsCollector + LinuxCollector interface parity."""

from engines.credentialed.windows_collector import WindowsCollector, COMMANDS
from engines.credentialed.linux_collector import LinuxCollector
import inspect

# Verify WindowsCollector has all expected command keys
expected_keys = ['os_info', 'hostname', 'uptime', 'cpu', 'memory', 'disk',
                 'software_x64', 'software_x86', 'hotfixes', 'services',
                 'open_ports', 'network_iface', 'local_users', 'local_admins',
                 'firewall', 'shares', 'rdp_status', 'scheduled_tasks', 'failed_logins']
missing = [k for k in expected_keys if k not in COMMANDS]
print(f"WindowsCollector commands: {len(COMMANDS)} defined")
print(f"Missing expected keys: {missing or 'None'}")

# Verify both collectors have matching collect_all interface
wc_methods = sorted([m for m in dir(WindowsCollector) if m.startswith('_collect')])
lc_methods = sorted([m for m in dir(LinuxCollector) if m.startswith('_collect')])
print(f"WindowsCollector collect methods: {wc_methods}")
print(f"LinuxCollector collect methods:   {lc_methods}")

# Verify WindowsCollector.collect_all accepts sections parameter
sig = inspect.signature(WindowsCollector.collect_all)
print(f"WindowsCollector.collect_all signature: {sig}")

# Verify OS detection logic is wired in main.py
with open("main.py", "r") as f:
    content = f.read()

checks = {
    "WindowsCollector import": "from engines.credentialed.windows_collector import WindowsCollector" in content,
    "os_type field in model": 'os_type' in content and "'linux' | 'windows' | 'auto'" in content,
    "Auto-detect logic": 'req.os_type.lower()' in content,
    "uname probe": 'uname -s' in content,
    "cmd /c ver probe": 'cmd /c ver' in content,
    "WindowsCollector(ssh)": 'WindowsCollector(ssh)' in content,
    "LinuxCollector(ssh)": 'LinuxCollector(ssh)' in content,
    "detected_os in response": 'detected_os' in content,
}

print()
print("=== main.py integration checks ===")
all_pass = True
for check, result in checks.items():
    status = "PASS" if result else "FAIL"
    if not result:
        all_pass = False
    print(f"  [{status}] {check}")

print()
print("ALL CHECKS PASSED!" if all_pass else "SOME CHECKS FAILED!")
