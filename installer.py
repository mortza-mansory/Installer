#!/usr/bin/env python3

import os
import subprocess
import sys
import shutil
import json
import time
import socket

WAF_ROOT = "/opt/waf_interface"
BACKEND_DIR = f"{WAF_ROOT}/waf-ghb"
FRONTEND_DIR = f"{WAF_ROOT}/waf-ghf"
VENV_PATH = f"{BACKEND_DIR}/venv"
SSL_DIR = "/etc/waf-ssl"
BACKEND_PORT = 8081
SERVICE_NAME = "waf-backend"

REQUIREMENTS = """
fastapi==0.115.12
uvicorn==0.32.1
python-multipart==0.0.20
psutil==6.1.1
websockets
sqlalchemy==2.0.40
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

def get_system_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except:
        result = run("hostname -I | awk '{print \$1}'", check=False)
        return result.stdout.decode().strip() if result else "0.0.0.0"

def check_service_running(service_name):
    result = run(f"systemctl is-active {service_name}", check=False)
    return result and result.returncode == 0

def check_port_listening(port):
    result = run(f"ss -tulnp | grep {port} || true", check=False)
    return result and str(port) in result.stdout.decode()

def clean_installation():
    print("\033[34m[Cleanup] Removing all WAF Interface components...\033[0m")
    run(f"sudo systemctl stop {SERVICE_NAME} apache2 || true")
    run(f"sudo systemctl disable {SERVICE_NAME} || true")
    run(f"sudo rm -f /etc/systemd/system/{SERVICE_NAME}.service")
    run("sudo systemctl daemon-reload")
    run("sudo rm -f /etc/apache2/sites-available/waf.conf")
    run("sudo rm -f /etc/apache2/sites-enabled/waf.conf")
    run(f"sudo rm -rf {SSL_DIR}")
    run(f"sudo rm -rf {WAF_ROOT}")
    print("\033[32mCleanup complete! All WAF Interface components removed.\033[0m")

def install_controller():
    CONTROLLER_DIR = f"{WAF_ROOT}/waf-ghc"
    SYMLINK_PATH = "/usr/local/bin/waf-interface"
    
    print("\033[34m[+] Installing WAF Controller...\033[0m")
    try:
        if not os.path.exists("waf-ghc"):
            raise FileNotFoundError("Controller source directory 'waf-ghc' not found!")
        
        run(f"sudo mkdir -p {CONTROLLER_DIR} && sudo chown $USER:$USER {CONTROLLER_DIR}")
        shutil.copytree("waf-ghc", CONTROLLER_DIR, dirs_exist_ok=True,
                       ignore=shutil.ignore_patterns('build*', 'CMake*', '*.o', '*.a'))
        
        executable = None
        for path in [f"{CONTROLLER_DIR}/build/waf-interface",
                    f"{CONTROLLER_DIR}/waf-interface",
                    f"{CONTROLLER_DIR}/waf-ghc"]:
            if os.path.exists(path):
                executable = path
                break
        
        if not executable:
            raise Exception("Could not find controller executable")
        
        run(f"sudo chmod +x {executable}")
        run(f"sudo ln -sf {executable} {SYMLINK_PATH}")
        print("\033[32mController installed successfully!\033[0m")
        return True
        
    except Exception as e:
        print(f"\033[31mError installing controller: {str(e)}\033[0m")
        return False

def create_first_user():
    print("\033[34m\n=== First Admin Account Setup ===\033[0m")
    while True:
        choice = input("Create admin account now? [Y/n]: ").strip().lower()
        if choice in ('', 'y', 'yes'):
            break
        elif choice in ('n', 'no'):
            print("\033[33mYou can create admin accounts later with: waf-interface --user-add\033[0m")
            return False
        else:
            print("\033[31mPlease enter 'y' or 'n'\033[0m")
    
    try:
        result = subprocess.run(
            "waf-interface --user-add",
            shell=True,
            check=False,
            stdin=sys.stdin,
            stdout=sys.stdout,
            stderr=sys.stderr
        )
        return result.returncode == 0
    except Exception as e:
        print(f"\033[31mError: {str(e)}\033[0m")
        return False

def debug_backend_failure():
    print("\n\033[36m=== DEBUGGING BACKEND FAILURE ===\033[0m")
    run(f"sudo systemctl status {SERVICE_NAME} --no-pager -l", check=False)
    run(f"sudo journalctl -u {SERVICE_NAME} --no-pager -n 100", check=False)
    run(f"ls -la {BACKEND_DIR}", check=False)
    run(f"{VENV_PATH}/bin/python3 --version", check=False)
    run(f"{VENV_PATH}/bin/pip list", check=False)
    run(f"sudo openssl x509 -in {SSL_DIR}/waf.crt -noout -text", check=False)
    sys.exit(1)

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--clean":
        clean_installation()
        return

    FRONTEND_IP = get_system_ip()
    BACKEND_IP = "0.0.0.0"

    print("\033[33m=== WAF Interface Installer ===\033[0m")

    print("\033[34m[1/8] Cleaning up previous installations...\033[0m")
    run(f"sudo systemctl stop apache2 {SERVICE_NAME} || true")
    run(f"sudo rm -rf {WAF_ROOT} /etc/apache2/sites-available/waf.conf")
    run("sudo find /etc/apache2/sites-enabled/ -type l -delete")

    print("\033[34m[2/8] Installing system dependencies...\033[0m")
    run("sudo apt-get update -y")
    run("sudo apt-get install -y apache2 openssl python3-venv libssl-dev")

    print("\033[34m[3/8] Creating project structure...\033[0m")
    try:
        required_dirs = ["waf-ghb", "waf-ghf", "waf-ghc"]
        for d in required_dirs:
            if not os.path.exists(d):
                raise FileNotFoundError(f"Source directory {d} not found!")

        run(f"sudo mkdir -p {WAF_ROOT} && sudo chown $USER:$USER {WAF_ROOT}")
        shutil.copytree("waf-ghb", BACKEND_DIR, ignore=shutil.ignore_patterns('venv*', '__pycache__'))
        shutil.copytree("waf-ghf", FRONTEND_DIR)
        shutil.copytree("waf-ghc", f"{WAF_ROOT}/waf-ghc")

    except Exception as e:
        print(f"\033[31mFATAL ERROR: {str(e)}\033[0m")
        sys.exit(1)

    print("\033[34m[4/8] Setting permissions...\033[0m")
    run(f"sudo chown -R www-data:www-data {WAF_ROOT}")
    run(f"sudo chmod -R 755 {WAF_ROOT}")

    print("\033[34m[5/8] Setting up Python environment...\033[0m")
    venv_cmd = f"sudo -u www-data /usr/bin/python3 -m venv {VENV_PATH} --clear --copies"
    if not run(venv_cmd):
        print("\033[31mFailed to create virtual environment!\033[0m")
        sys.exit(1)

    processed_requirements = REQUIREMENTS.strip().replace('\n', ' ')    
    pip_cmd = f"sudo -u www-data {VENV_PATH}/bin/pip install --no-cache-dir --disable-pip-version-check {processed_requirements}"
    if not run(pip_cmd):
        print("\033[31mFailed to install Python requirements!\033[0m")
        sys.exit(1)

    print("\033[34m[6/8] Generating SSL certificates...\033[0m")
    run(f"sudo mkdir -p {SSL_DIR} && sudo chown www-data:www-data {SSL_DIR}")
    
    openssl_config = f"""
[req]
default_bits = 2048
prompt = no
default_md = sha256
x509_extensions = v3_req
distinguished_name = dn

[dn]
CN = {FRONTEND_IP}

[v3_req]
subjectAltName = @alt_names

[alt_names]
IP.1 = 127.0.0.1
IP.2 = {FRONTEND_IP}
"""
    
    with open("/tmp/openssl.cnf", "w") as f:
        f.write(openssl_config)
    
    run(f"sudo -u www-data openssl req -x509 -nodes -days 365 -newkey rsa:2048 "
        f"-config /tmp/openssl.cnf "
        f"-keyout {SSL_DIR}/waf.key -out {SSL_DIR}/waf.crt")
    
    run(f"sudo chmod 644 {SSL_DIR}/waf.crt")
    run(f"sudo chmod 600 {SSL_DIR}/waf.key")

    print("\033[34m[7/8] Updating frontend configuration...\033[0m")
    config_path = os.path.join(FRONTEND_DIR, "assets", "assets", "config.json")
    with open(config_path, "r+") as f:
        config = json.load(f)
        config["http_address"] = f"https://{FRONTEND_IP}:{BACKEND_PORT}"
        config["websocket_address"] = f"wss://{FRONTEND_IP}:{BACKEND_PORT}/ws"
        f.seek(0)
        json.dump(config, f, indent=2)
        f.truncate()

    # Apache config
    print("\033[34m[8/8] Configuring Apache...\033[0m")
    apache_conf = f"""
<VirtualHost {FRONTEND_IP}:80>
    Redirect permanent / https://{FRONTEND_IP}/
</VirtualHost>

<VirtualHost {FRONTEND_IP}:443>
    SSLEngine on
    SSLCertificateFile {SSL_DIR}/waf.crt
    SSLCertificateKeyFile {SSL_DIR}/waf.key
    
    DocumentRoot {FRONTEND_DIR}
    <Directory {FRONTEND_DIR}>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
"""
    with open("/tmp/waf.conf", "w") as f:
        f.write(apache_conf)
        
    run("sudo mv /tmp/waf.conf /etc/apache2/sites-available/")
    run("sudo a2enmod ssl headers rewrite")
    run("sudo a2ensite waf")

    print("\033[34m[9/9] Setting up backend service...\033[0m")
    service_content = f"""
[Unit]
Description=WAF Backend
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory={BACKEND_DIR}
Environment="PATH={VENV_PATH}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStartPre=/bin/sh -c 'fuser -k {BACKEND_PORT}/tcp || true'
ExecStart={VENV_PATH}/bin/python3 -m uvicorn app:app --host {BACKEND_IP} --port {BACKEND_PORT} --ssl-keyfile {SSL_DIR}/waf.key --ssl-certfile {SSL_DIR}/waf.crt
Restart=on-failure
RestartSec=5
KillMode=process

[Install]
WantedBy=multi-user.target
"""
    with open("/tmp/waf-backend.service", "w") as f:
        f.write(service_content)
        
    run(f"sudo mv /tmp/waf-backend.service /etc/systemd/system/{SERVICE_NAME}.service")
    run("sudo systemctl daemon-reload")

    print("\033[34mStarting services...\033[0m")
    run(f"sudo lsof -ti:{BACKEND_PORT} | xargs -r sudo kill -9")
    run(f"sudo systemctl enable --now {SERVICE_NAME}")

    if not install_controller():
        sys.exit(1)

    if not create_first_user():
        print("\033[33mUser creation skipped or failed\033[0m")

    print("\033[34mVerifying SSL configuration...\033[0m")
    run(f"sudo openssl x509 -in {SSL_DIR}/waf.crt -noout -text | grep -A1 'Subject Alternative Name'")

    max_retries = 5
    for attempt in range(max_retries):
        print(f"\033[34mVerifying backend (attempt {attempt + 1}/{max_retries})...\033[0m")
        if check_service_running(SERVICE_NAME) and check_port_listening(BACKEND_PORT):
            break
        time.sleep(5)
    else:
        debug_backend_failure()

    run("sudo systemctl restart apache2")

    print(f"\033[32m\nInstall complete! Access frontend at: https://{FRONTEND_IP}\033[0m")
    print(f"\033[32mBackend running on: https://{FRONTEND_IP}:{BACKEND_PORT}\033[0m")
    print(f"\033[33mTo remove installation: sudo {sys.argv[0]} --clean\033[0m")

if __name__ == "__main__":
    main()
