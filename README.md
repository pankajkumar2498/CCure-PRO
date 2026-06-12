# CCure-Audit-PRO
Network Scanning Tool

Inside /Backend Folder:

python -m venv .venv

.venv\Scripts\Activate.ps1

pip install -r requirements.txt




# Run all containers/Project
.\scripts\start_host_scan_stack.ps1

# Stop all containers
 .\scripts\stop_host_scan_stack.ps1


# For Running Worker for Nmap Scans locally
.\Backend\scripts\start_host_scanner_worker.ps1     // Run when all dockers are up and showing error in Nmap worker 

# Scanner worker concurrency
# Default is 20 parallel scan tasks. Override before starting the worker if needed:
$env:SCANNER_WORKER_CONCURRENCY="30"
$env:MAX_NMAP_PROCESSES="20"   # global Nmap process cap; raise only if the scanner host can handle it
.\Backend\scripts\start_host_scanner_worker.ps1









# Download next 1000 (offset 3300)
python scripts/download_nvd.py --limit 1000 --offset 3300

# Then next batch (offset shown in output)
python scripts/download_nvd.py --limit 1000 --offset 4300

# Then next batch (offset shown in output)
python scripts/download_nvd.py --limit 1000 --offset 12500
# And so on...

python test_cve_db.py    # Quick test









 # On Windows target machine
Set-ExecutionPolicy Bypass -Scope Process -Force
.\Prepare-WindowsForVulnScan.ps1
Restart-Computer

# Wait 10 minutes for restart

# From scanner machine
.\Verify-WindowsScanReadiness.ps1 -TargetComputer 10.180.6.14
# Check: All tests pass ✓





Your Windows scanning will only work if the target has OpenSSH Server configured correctly. You should surface this to users in the UI and/or docs. The target Windows machine needs:
powershell# Install OpenSSH Server (run as Administrator on target)
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'

# Set PowerShell as default shell (required for your PS commands to work)
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" `
    -Name DefaultShell `
    -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
    -PropertyType String -Force






# To update your production database (ccure_db) with the latest migrations, you have two options. Since you are on Windows, here are the commands depending on whether you are using PowerShell or Command Prompt (CMD):

Option 1: Explicitly pass the production DATABASE_URL (Recommended & Safest)
Setting the database URL directly in your terminal is the safest and most bulletproof way because it forces Alembic to connect to ccure_db without you having to worry about which .env file it is loading.

If you are using PowerShell:
powershell
cd Backend
$env:DATABASE_URL="postgresql://ccure_user:ccure_admin_2026@127.0.0.1:5432/ccure_db"
.venv\Scripts\python.exe -m alembic upgrade head
Remove-Item Env:DATABASE_URL


If you are using Command Prompt (CMD):
cmd
cd Backend
set DATABASE_URL=postgresql://ccure_user:ccure_admin_2026@127.0.0.1:5432/ccure_db
.venv\Scripts\python.exe -m alembic upgrade head
set DATABASE_URL=



Option 2: Use APP_ENV=production to load the production Backend/.env file
Alembic's configuration is built to load Backend/.env (which points to ccure_db) whenever APP_ENV is set to production.

If you are using PowerShell:
powershell
cd Backend
$env:APP_ENV="production"
.venv\Scripts\python.exe -m alembic upgrade head
Remove-Item Env:APP_ENV
If you are using Command Prompt (CMD):
cmd
cd Backend
set APP_ENV=production
.venv\Scripts\python.exe -m alembic upgrade head
set APP_ENV=







# To move all the actual data (scans, users, assets, etc.) from your development/test database (ccure_test) to your production database (ccure_db), you can use PostgreSQL's built-in backup and restore utilities.

Here are the step-by-step methods to do this using either the command line or a GUI tool (like pgAdmin or DBeaver).

Important: Stop your Backend first
Before copying the data, stop the FastAPI backend and Celery workers (both Docker and local host scanner). Otherwise, active connections will lock the databases and prevent them from being dropped or restored.

Method 1: Using the Command Line (PowerShell)
PostgreSQL includes command-line tools called pg_dump and pg_restore.

Note: If PowerShell says these commands are not recognized, you will need to add the path of your PostgreSQL installation to the command (e.g., prefixing them with & "C:\Program Files\PostgreSQL\<version>\bin\pg_dump.exe").

Dump the source database (ccure_test) to a file:

powershell
pg_dump -U ccure_user -h 127.0.0.1 -d ccure_test -F c -b -v -f ccure_test_backup.dump
(When prompted, enter the password: ccure_admin_2026)

Recreate the destination database (ccure_db): Restoring on top of an existing database can cause duplicate key errors. It is best to drop and recreate an empty ccure_db first:

powershell
dropdb -U ccure_user -h 127.0.0.1 ccure_db
createdb -U ccure_user -h 127.0.0.1 ccure_db
Restore the dump into the new ccure_db:

powershell
pg_restore -U ccure_user -h 127.0.0.1 -d ccure_db -v ccure_test_backup.dump
(When prompted, enter the password: ccure_admin_2026)

Once finished, your ccure_db database will have the exact same schema, tables, data, indexes, and migrations history as ccure_test.

Method 2: Using pgAdmin
If you prefer pgAdmin, you can do this visually:

Open pgAdmin and connect to your local server.
Expand Databases -> Right-click on ccure_test -> Select Backup...
Under General, enter a filename (e.g., ccure_test_backup).
Click the Backup button at the bottom right.
Drop and recreate ccure_db to ensure a clean slate:
Right-click on ccure_db -> Select Delete/Drop.
Right-click on Databases -> Select Create -> Database... Name it ccure_db and save.
Right-click on ccure_db -> Select Restore...
Under General, select the backup file you just created (ccure_test_backup).
Click Restore.
Method 3: Using DBeaver
If you use DBeaver:

Right-click on ccure_test -> Select Tools -> Backup database.
Keep default settings, choose an output folder, and click Start.
Right-click on ccure_db -> Select Delete (confirm to drop it).
Right-click on your PostgreSQL connection -> Select Create -> Database. Name it ccure_db.
Right-click on the new ccure_db -> Select Tools -> Restore database.
Choose the backup file created in step 1, and click Start.








# if we change Frontend Port in docker-compose.yml then do below things:

Why this happens
To capture real client IP addresses on Docker Desktop (Windows), a host-level Nginx service listening on port 80 proxies requests:

/api/* requests go to your backend container at 127.0.0.1:8000.
All other requests (/*) were being proxied to 127.0.0.1:3000.
When you changed the frontend container port mapping from 3000 to 3200, Nginx continued trying to forward traffic to 127.0.0.1:3000. Since nothing is listening on port 3000 anymore, Nginx returned a 502 Bad Gateway.

What has been updated
I have modified the configuration files in your workspace to point to the new port:

CCure-Audit-PRO\scripts\host-nginx\nginx-host.conf: Updated the proxy pass destination to port 3200 (proxy_pass http://127.0.0.1:3200;).

CCure-Audit-PRO\.env: Added the new 3200 port variants to CORS_ALLOW_ORIGINS to ensure the FastAPI backend accepts requests from the new port configurations.

How to apply this fix on your machine
Since the Nginx server runs as a Windows Service directly on the host machine, you need to copy the updated configuration and restart the service.

Open PowerShell as Administrator.
Run the following commands:
powershell
# 1. Copy the updated config file to your Nginx installation folder
Copy-Item -Path "c:\Users\pankaj\Downloads\Automation Tool\CCure-Audit-PRO\scripts\host-nginx\nginx-host.conf" -Destination "C:\nginx\conf\nginx.conf" -Force
# 2. Restart the Nginx Windows service to apply the new configuration
Restart-Service -Name CCureNginx
Once Nginx restarts, you should be able to access the application again at http://10.180.6.14/login