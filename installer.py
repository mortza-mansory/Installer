#!/usr/bin/env python3

import os
import subprocess
import sys
import shutil
import json
import time

WAF_ROOT = "/opt/waf_interface"
BACKEND_DIR = f"{WAF_ROOT}/waf-ghb"
FRONTEND_DIR = f"{WAF_ROOT}/waf-ghf"
VENV_PATH = f"{BACKEND_DIR}/venv"
SSL_DIR = "/etc/ssl/private"
BACKEND_PORT = 8081
SERVICE_NAME = "waf-backend"

REQUIREMENTS = """
fastapi==0.115.6
uvicorn==0.32.1
python-multipart==0.0.20
psutil==6.1.1
websockets
sqlalchemy==2.0.25
pymysql==1.1.0
python-jose==3.3.0
passlib==1.7.4
pydantic==2.11.2
starlette==0.41.3
alembic==1.13.1
sqlalchemy-utils==0.41.1
PyJWT==2.10.1
cryptography==44.0.2
python-dotenv==0.20.0 
"""

def run(cmd, check=True):
    try:
        result = subprocess.run(cmd, shell=True, check=check,
                              executable="/bin/bash",
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
        return result
    except subprocess.CalledProcessError as e:
        print(f"\033[31mFAILED: {cmd}\033[0m")
        print(f"Error: {e.stderr.decode().strip()}")
        return None

def check_service_running(service_name):
    result = run(f"systemctl is-active {service_name}", check=False)
    return result and result.returncode == 0

def check_port_listening(port):
    result = run(f"ss -tulnp | grep {port} || true", check=False)
    return result and str(port) in result.stdout.decode()

def debug_backend_failure():
    print("\n\033[36m=== DEBUGGING BACKEND FAILURE ===\033[0m")
    
    # 1. Check service status with full output
    print("\n\033[33m1. Service Status:\033[0m")
    run(f"sudo systemctl status {SERVICE_NAME} --no-pager -l", check=False)
    
    # 2. Full journal logs
    print("\n\033[33m2. Journal Logs:\033[0m")
    run(f"sudo journalctl -u {SERVICE_NAME} --no-pager -n 100", check=False)
    
    # 3. Verify backend files exist
    print("\n\033[33m3. Backend Files Check:\033[0m")
    run(f"ls -la {BACKEND_DIR}", check=False)
    run(f"ls -la {BACKEND_DIR}/app.py", check=False)
    
    # 4. Check Python environment
    print("\n\033[33m4. Python Environment Check:\033[0m")
    run(f"{VENV_PATH}/bin/python3 --version", check=False)
    run(f"{VENV_PATH}/bin/pip list", check=False)
    
    # 5. Validate permissions
    print("\n\033[33m5. Permission Checks:\033[0m")
    run(f"ls -ld {WAF_ROOT}", check=False)
    run(f"ls -l {BACKEND_DIR}/venv", check=False)
    
    # 6. Attempt manual startup with full output
    print("\n\033[33m6. Manual Startup Attempt:\033[0m")
    cmd = f"sudo -u www-data {VENV_PATH}/bin/python3 -m uvicorn app:app --host 0.0.0.0 --port {BACKEND_PORT}"
    print(f"Running: {cmd}")
    try:
        subprocess.run(cmd, shell=True, check=True, executable="/bin/bash")
    except subprocess.CalledProcessError as e:
        print("\033[31mManual startup failed with:\033[0m")
        if e.stderr is not None:
            print(e.stderr.decode())
        else:
            print("No error output available.")
    
    print("\n\033[31mDEBUGGING COMPLETE. Check output above for errors.\033[0m")
    sys.exit(1)

def clean_installation():
    print("\033[34m[Cleanup] Removing all WAF Interface components...\033[0m")
    
    run(f"sudo systemctl stop {SERVICE_NAME} apache2 || true")
    run(f"sudo systemctl disable {SERVICE_NAME} || true")
    
    run(f"sudo rm -f /etc/systemd/system/{SERVICE_NAME}.service")
    run("sudo systemctl daemon-reload")
    
    run("sudo rm -f /etc/apache2/sites-available/waf.conf")
    run("sudo rm -f /etc/apache2/sites-enabled/waf.conf")
    
    run(f"sudo rm -f {SSL_DIR}/waf.key {SSL_DIR}/waf.crt")
    
    run(f"sudo rm -rf {WAF_ROOT}")
    
    print("\033[32mCleanup complete! All WAF Interface components have been removed.\033[0m")

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--clean":
        clean_installation()
        return
   
    print("\033[33m=== WAF Interface Installer ===\033[0m")

    print("\033[34m[1/8] Cleaning up previous installations...\033[0m")
    run(f"sudo systemctl stop apache2 {SERVICE_NAME} || true")
    run(f"sudo rm -rf {WAF_ROOT} /etc/apache2/sites-available/waf.conf")
    run("sudo find /etc/apache2/sites-enabled/ -type l -delete")

    print("\033[34m[2/8] Installing system dependencies...\033[0m")
    run("sudo apt-get update -y")
    run("sudo apt-get install -y apache2 libapache2-mod-wsgi-py3 openssl python3-venv")

    print("\033[34m[3/8] Creating project structure...\033[0m")
    try:
        run(f"sudo mkdir -p {WAF_ROOT} && sudo chown $USER:$USER {WAF_ROOT}")
        
        print(f"Copying backend files to {BACKEND_DIR}")
        if not os.path.exists("waf-ghb"):
            raise FileNotFoundError("Source directory waf-ghb not found!")
        shutil.copytree("waf-ghb", BACKEND_DIR,
                       ignore=shutil.ignore_patterns('venv*', '__pycache__'))

        print(f"Copying frontend files to {FRONTEND_DIR}")
        if not os.path.exists("waf-ghf"):
            raise FileNotFoundError("Source directory waf-ghf not found!")
        shutil.copytree("waf-ghf", FRONTEND_DIR)

    except Exception as e:
        print(f"\033[31mFATAL ERROR: {str(e)}\033[0m")
        sys.exit(1)

    print("\033[34m[4/8] Setting permissions...\033[0m")
    run(f"sudo chown -R www-data:www-data {WAF_ROOT}")
    run(f"sudo chmod -R 755 {WAF_ROOT}")

    print("\033[34m[5/8] Setting up Python environment...\033[0m")
    python_path = run("which python3").stdout.decode().strip()
    venv_cmd = f"sudo -u www-data {python_path} -m venv {VENV_PATH} --clear --copies"
    if not run(venv_cmd):
        print("\033[31mFailed to create virtual environment!\033[0m")
        sys.exit(1)
        
    requirements = ' '.join(REQUIREMENTS.strip().split())
    pip_cmd = f"sudo -u www-data {VENV_PATH}/bin/pip install --no-cache-dir --disable-pip-version-check {requirements}"
    if not run(pip_cmd):
        print("\033[31mFailed to install Python requirements!\033[0m")
        sys.exit(1)

    if not os.path.exists(f"{VENV_PATH}/bin/python"):
        run(f"sudo -u www-data ln -s {VENV_PATH}/bin/python3 {VENV_PATH}/bin/python")
    if not os.path.exists(f"{VENV_PATH}/bin/python3"):
        run(f"sudo -u www-data ln -s {python_path} {VENV_PATH}/bin/python3")

    run(f"sudo chmod -R +x {VENV_PATH}/bin")

    print("\033[34m[6/8] Generating SSL certificates...\033[0m")
    ip = subprocess.getoutput("hostname -I | awk '{print $1}'").strip()
    run(f"sudo mkdir -p {SSL_DIR}")
    run(f"sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 "
        f"-keyout {SSL_DIR}/waf.key -out {SSL_DIR}/waf.crt "
        f"-subj '/CN={ip}' -addext 'subjectAltName=IP:{ip}'")
    run(f"sudo chmod 640 {SSL_DIR}/waf.key {SSL_DIR}/waf.crt")
    run(f"sudo chown www-data:www-data {SSL_DIR}/waf.key {SSL_DIR}/waf.crt")

    print("\033[34m[7/8] Updating frontend configuration...\033[0m")
    config_path = os.path.join(FRONTEND_DIR, "assets", "assets", "config.json")
    with open(config_path, "r+") as f:
        config = json.load(f)
        config["http_address"] = f"https://{ip}/api"
        config["websocket_address"] = f"wss://{ip}/ws"
        f.seek(0)
        json.dump(config, f, indent=2)
        f.truncate()

    print("\033[34m[8/8] Configuring Apache...\033[0m")
    with open("/tmp/waf.conf", "w") as f:
        f.write(f"""
<VirtualHost *:80>
    Redirect permanent / https://{ip}/
</VirtualHost>

<VirtualHost *:443>
    SSLEngine on
    SSLCertificateFile {SSL_DIR}/waf.crt
    SSLCertificateKeyFile {SSL_DIR}/waf.key
    
    DocumentRoot {FRONTEND_DIR}
    
    ProxyPass /api http://127.0.0.1:{BACKEND_PORT}/api
    ProxyPassReverse /api http://127.0.0.1:{BACKEND_PORT}/api
    ProxyPass /ws ws://127.0.0.1:{BACKEND_PORT}/ws
    ProxyPassReverse /ws ws://127.0.0.1:{BACKEND_PORT}/ws
    
    <Directory {FRONTEND_DIR}>
        AllowOverride All
        Require all granted
    </Directory>
    
    Header always set Access-Control-Allow-Origin "*"
    Header always set Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS"
    Header always set Access-Control-Allow-Headers "Content-Type, Authorization"
    
    SSLProxyEngine off
    ProxyPreserveHost On
    ProxyRequests Off
    RequestHeader set X-Forwarded-Proto "https"
    RequestHeader set X-Forwarded-For $proxy_add_x_forwarded_for
</VirtualHost>
""")
    run("sudo mv /tmp/waf.conf /etc/apache2/sites-available/")
    run("sudo a2enmod ssl proxy proxy_http proxy_wstunnel headers proxy_http2")
    run("sudo a2ensite waf")

    print("\033[34m[9/9] Setting up backend service...\033[0m")
    with open("/tmp/waf-backend.service", "w") as f:
        f.write(f"""
[Unit]
Description=WAF Backend
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory={BACKEND_DIR}
Environment="PATH={VENV_PATH}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="PYTHONPATH={BACKEND_DIR}:{VENV_PATH}/lib/python3.11/site-packages"
ExecStart={VENV_PATH}/bin/python3 -m uvicorn app:app --host 0.0.0.0 --port {BACKEND_PORT}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
""")
    run(f"sudo mv /tmp/waf-backend.service /etc/systemd/system/{SERVICE_NAME}.service")
    run("sudo systemctl daemon-reload")

    print("\033[34mStarting services...\033[0m")
    run(f"sudo systemctl enable --now {SERVICE_NAME}")

    max_retries = 5
    for attempt in range(max_retries):
        print(f"\033[34mVerifying backend (attempt {attempt + 1}/{max_retries})...\033[0m")
        if check_service_running(SERVICE_NAME) and check_port_listening(BACKEND_PORT):
            break
        time.sleep(5)
    else:
        print(f"\033[31mBackend service failed to start after {max_retries} attempts!\033[0m")
        debug_backend_failure()

    run("sudo systemctl restart apache2")

    print("\033[34mFinal verification...\033[0m")
    if not check_service_running("apache2"):
        print("\033[31mApache service failed to start! Checking logs...\033[0m")
        run("sudo journalctl -u apache2 -n 50 --no-pager")
        sys.exit(1)

    print(f"\033[32mInstall complete! Access at: https://{ip}\033[0m")
    print(f"\033[32mBackend running on: http://127.0.0.1:{BACKEND_PORT}\033[0m")
    print("\033[32mAll services are running correctly.\033[0m")
    print(f"\033[33mTo completely remove the installation, run: sudo {sys.argv[0]} --clean\033[0m")
    
if __name__ == "__main__":
    main()
