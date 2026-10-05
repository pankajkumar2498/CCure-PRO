# CCure-Audit-PRO
Network Scanning Tool

Frontend development follows the permanent [UX4G standard](docs/ux4g/UX4G_STANDARD.md).
All modules share the exact approved release, central asset pipeline and CCure
adapters. See [Frontend/README.md](Frontend/README.md) for required CI checks
and [the final migration report](docs/ux4g/B7_B10_FINAL_CLOSURE.md) for validation.

Inside /Backend Folder:

python -m venv .venv

.venv\Scripts\Activate.ps1

pip install -r requirements.txt




# Run all containers/Project
.\scripts\start_host_scan_stack.ps1

# Stop all containers
 .\scripts\stop_host_scan_stack.ps1


# For Running Worker for Nmap Scans locally
.\Backend\scripts\scan\start_host_scanner_worker.ps1     // Run when all dockers are up and showing error in Nmap worker

# Scanner worker concurrency
# Default is 20 parallel scan tasks. Override before starting the worker if needed:
$env:SCANNER_WORKER_CONCURRENCY="30"
$env:MAX_NMAP_PROCESSES="20"   # global Nmap process cap; raise only if the scanner host can handle it
.\Backend\scripts\scan\start_host_scanner_worker.ps1









# Download next 1000 (offset 3300)
python scripts/vuln/download_nvd.py --limit 1000 --offset 3300

# Then next batch (offset shown in output)
python scripts/vuln/download_nvd.py --limit 1000 --offset 4300

# Then next batch (offset shown in output)
python scripts/vuln/download_nvd.py --limit 1000 --offset 12500
# And so on...

python scripts/verification/check_cve_source.py    # Confirm which CVE source is in use









 # On Windows target machine
Set-ExecutionPolicy Bypass -Scope Process -Force
.\Prepare-WindowsForVulnScan.ps1
Restart-Computer

# Wait 10 minutes for restart

# From scanner machine
.\Verify-WindowsScanReadiness.ps1 -TargetComputer 10.180.6.14
# Check: All tests pass ✓






# If Fresh Machine came into Network then follow below Procedure to make it successfull scan through Credentialed Scan
# Enable OpenSSH Server (Manually on Traget Machine)
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -ErrorAction SilentlyContinue
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'

# Set PowerShell as default shell
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force

# Open Firewall Port 22
New-NetFirewallRule -Name "OpenSSH-In" -DisplayName "Allow OpenSSH Port 22" -Enabled True -Profile Any -Direction Inbound -Action Allow -Protocol TCP -LocalPort 22 -ErrorAction SilentlyContinue

#
Restart-Service sshd


# Run inside Powershell (On Target Machine)
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 1 -PropertyType DWord -Force





# Do it from Source Machine (Prerequisite - SSH should be enabled on Target Machine to run below commands)
# First take SSH of Target Machine bu using :
  ssh username@IP

Option 1: Start PowerShell first (Recommended)

1.  Switch shell:
    Type powershell in cmd terminal your SSH session to switch to a PowerShell environment, then run the commands:
    powershell

2.  Run the commands:
    New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
Restart-Service sshd


Option 2: Alternatively, we can run them directly from your current cmd prompt by wrapping them in powershell -Command:

powershell -Command "New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -PropertyType String -Force"

powershell -Command "Restart-Service sshd"

# IMPORTANT
Because you are modifying registry keys under HKLM (Local Machine) and restarting a system service (sshd), the cdac user account must have Administrator privileges, and UAC must allow remote elevation. If you receive an "Access Denied" error, make sure you ran the LocalAccountTokenFilterPolicy registry fix first.



















# To update your production database (ccure_db) with the latest migrations, you have two options. Since you are on Windows, here are the commands depending on whether you are using PowerShell or Command Prompt (CMD):

Option 1: Explicitly pass the production DATABASE_URL (Recommended & Safest)
Setting the database URL directly in your terminal is the safest and most bulletproof way because it forces Alembic to connect to ccure_db without you having to worry about which .env file it is loading.

If you are using PowerShell:
powershell
cd Backend
$env:DATABASE_URL="postgresql://ccure_user:ccure_admin_2026@127.0.0.1:5432/ccure_db"
.venv\Scripts\python.exe -m alembic upgrade heads
Remove-Item Env:DATABASE_URL


If you are using Command Prompt (CMD):
cmd
cd Backend
set DATABASE_URL=postgresql://ccure_user:ccure_admin_2026@127.0.0.1:5432/ccure_db
.venv\Scripts\python.exe -m alembic upgrade heads
set DATABASE_URL=



Option 2: Use APP_ENV=production to load the production Backend/.env file
Alembic's configuration is built to load Backend/.env (which points to ccure_db) whenever APP_ENV is set to production.

If you are using PowerShell:
powershell
cd Backend
$env:APP_ENV="production"
.venv\Scripts\python.exe -m alembic upgrade heads
Remove-Item Env:APP_ENV
If you are using Command Prompt (CMD):
cmd
cd Backend
set APP_ENV=production
.venv\Scripts\python.exe -m alembic upgrade heads
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










## Running the Application Stack

### Startup Commands

To start the hybrid docker/host stack, run the following PowerShell scripts:

* **Normal Startup (Instant)**:
  Reuses existing containers. Use this for regular day-to-day development:
  ```powershell
  .\scripts\start_host_scan_stack.ps1
  ```
* **Full Rebuild**:
  Rebuilds all container images from scratch. Use this only when dependency configs (`requirements.txt`, `package.json`) or Docker files change:
  ```powershell
  .\scripts\start_host_scan_stack.ps1 -Rebuild
  ```
* **Targeted Rebuild**:
  Rebuilds and starts a specific service container (e.g. `frontend` or `api`):
  ```powershell
  .\scripts\start_host_scan_stack.ps1 -Rebuild -Service frontend
  ```
* **Force Recreate**:
  Forces recreation of all containers without rebuilding images:
  ```powershell
  .\scripts\start_host_scan_stack.ps1 -Recreate
  ```

### Optimized Local Development Workflow (Industry Standard)

To avoid rebuilding/restarting all containers for minor frontend or backend edits, use these targeted developer commands:

1. **For Frontend Development (React / CSS / JSX)**:
   - Start the backend dependencies in Docker:
     ```powershell
     .\scripts\start_host_scan_stack.ps1
     ```
   - Run the hot-reloading development server directly on your host machine:
     ```powershell
     cd Frontend
     npm run dev
     ```
     * Vite will serve the frontend at `http://localhost:3000` with instant Hot Module Replacement (under 100ms) and route API queries automatically to Docker on `http://localhost:8000`.

2. **For Backend Development (FastAPI)**:
   - The backend codebase (`./Backend`) is mounted as a container volume. Changes are live instantly inside Docker.
   - If you want to force restart only the API worker to reload the code:
     ```powershell
     docker compose restart api
     ```
   - To monitor container logs live in real-time:
     ```powershell
     docker compose logs -f api
     ```
















































# CI/CD Pipeline
Here is the step-by-step guide to verifying all the newly implemented QA and regression components locally on your machine.

Since you are running Windows with PowerShell and have your virtual environment active, run these commands inside your terminal:

Step 1: Run the Automated Regression Test Suite
First, we will run the new test cases we added to verify that RBAC mapping, the Maker-Checker self-approval block, the PDF report visual layout, and the process leak detection fixture are all working perfectly.

Run the following in your PowerShell terminal:

powershell
# Ensure you are in the Backend folder
cd "c:\Users\pankaj\Downloads\Automation Tool\CCure-Audit-PRO\Backend"
# Enable local scanner mocking so you don't need nmap/scapy binaries installed on your host OS
$env:MOCK_SCANNERS="true"
# Execute our new regression test modules
pytest tests/security/test_rbac_routes.py tests/compliance/test_remediation_safety.py tests/reports/test_report_limits.py -v
Expected Output: All three test suites should execute and print PASSED.

Step 2: Register and Verify Git Pre-commit Hooks
Next, install and register the local pre-commit hooks so formatting and AST security scans run automatically before every Git commit:

powershell
# 1. Move to the repository root directory
cd "c:\Users\pankaj\Downloads\Automation Tool\CCure-Audit-PRO"
# 2. Install pre-commit tool (via your active python virtualenv)
pip install pre-commit
# 3. Register the hooks in your local .git directory
pre-commit install
# 4. (Optional) Run all checks manually across existing files to verify setup:
pre-commit run --all-files
Expected Output: You should see pre-commit download and run checks (Black, Ruff, Bandit, Prettier, ESLint) across the codebase.

Step 3: Establish the OpenAPI Schema Baseline
To enable the CI/CD pipeline to catch breaking API changes, generate the baseline openapi.json contract file:

powershell
# Move to the Backend folder
cd "c:\Users\pankaj\Downloads\Automation Tool\CCure-Audit-PRO\Backend"
# Generate the initial schema definition file
python -c "import json; from main import app; print(json.dumps(app.openapi()))" > openapi.json
Verification: This creates a file named openapi.json in your Backend/ folder. Add and commit this file to your git repository (git add openapi.json). Any future PR that changes paths or formats will now be checked against this file in CI.

Step 4: Verify CI/CD Automation
To verify the GitHub Actions setup, simply push your changes to a branch or open a Pull Request. GitHub will automatically spin up PostgreSQL and Redis service containers, run the Alembic migration integrity loops, perform the security/dependency audits, and run the test suite inside the test container.



















































Step 1: Start Backend & Scanner Stack
Run this command once in your Administrator PowerShell window:
    .\scripts\start_host_scan_stack.ps1

What this does: It instantly starts the containerized database, Redis, API server, and web worker, and also starts your Windows host scanner worker.

Step 2: Start Frontend Dev Server
Open a new, separate PowerShell window (it does not need to be Administrator), navigate to the Frontend folder, and start the Vite dev server:

cd "c:\Users\pankaj\Downloads\Automation Tool\CCure-Audit-PRO\Frontend"
    npm run dev
What this does: It launches the hot-reloading React dev server on your host machine.
Access the App: Open your browser and go to: http://localhost:3000

How Changes Reflect Immediately:
1. Editing Frontend Files (CSS / JSX / JS)
What to do: Just edit and save the files in your editor (e.g. VS Code).
How it reflects: Instantly (under 100ms). Vite will hot-reload only the modified components in your browser tab at http://localhost:3000 without rebuilding any containers or reloading the page.

2. Editing Backend Files (Python)
What to do: Just edit and save your Python code.
How it reflects: Instantly. Because the ./Backend directory is volume-mounted directly into the API container, Uvicorn detects your changes and hot-reloads the Python server automatically.

3. Adding New Packages/Dependencies (Only when needed)
If you change Python requirements: Rebuild only the API container:

.\scripts\start_host_scan_stack.ps1 -Rebuild -Service api

If you add Frontend npm packages: Press Ctrl+C in your frontend terminal to stop Vite, run npm install, and then restart with npm run dev.





For the Frontend (PowerShell version)
Run the commands separated by ;:

docker compose build frontend; docker compose up -d frontend
(Or simply run docker compose build frontend first, then run docker compose up -d frontend after it finishes).

For the Backend / Workers Restart
Since worker and web-worker use Docker profiles (profiles: ["container-scanner"]), standard docker compose commands might ignore them if the profile isn't explicitly active. To make sure they are restarted, include the --profile flag:

docker compose --profile container-scanner restart api worker web-worker


OR

 .\scripts\start_host_scan_stack.ps1

 docker compose --profile container-scanner restart api worker web-worker

 docker compose build frontend; docker compose up -d frontend

 docker compose --profile container-scanner up -d worker  (Celery worker)

 docker compose down -v

 docker compose restart api










 Backend\.venv\Scripts\python -m scripts.seed_real_rules
