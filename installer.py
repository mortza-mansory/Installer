#!/usr/bin/env python3

import os
import subprocess
import sys
import socket
import shutil
import base64
import re
import json

# Constants
WAF_ROOT = "/opt/waf_interface"  # Project root directory
PROJECT_DIR = WAF_ROOT
BACKEND_DIR = os.path.join(WAF_ROOT, "waf-ghb")
FRONTEND_DIR = os.path.join(WAF_ROOT, "waf-ghf")
VENV_PATH = os.path.join(BACKEND_DIR, "venv")
NGINX_VERSION = "1.23.0"
MODSEC_NGINX_REPO = "https://github.com/owasp-modsecurity/ModSecurity-nginx.git"
OWASP_CRS_REPO = "https://github.com/coreruleset/coreruleset.git"
SSL_DIR = "/etc/ssl/private"
APACHE_PORTS_CONF = "/etc/apache2/ports.conf"
APACHE_SITES_AVAILABLE = "/etc/apache2/sites-available"
NGINX_CONF_DIR = "/usr/local/nginx/conf"
NGINX_SBIN = "/usr/local/nginx/sbin/nginx"
BACKEND_PORT = 8081  # Updated to match app.py

REQUIREMENTS = """
annotated-types==0.7.0
anyio==4.6.2.post1
bcrypt==4.2.1
click==8.1.7
fastapi==0.115.6
greenlet==3.1.1
h11==0.14.0
idna==3.10
passlib==1.7.4
pydantic==2.10.3
pydantic_core==2.27.1
PyJWT==2.10.1
pyotp==2.9.0
python-dotenv==1.0.1
redis==5.2.0
sniffio==1.3.1
SQLAlchemy==2.0.36
starlette==0.41.3
typing_extensions==4.12.2
uvicorn==0.32.1
psutil==6.1.1
python-multipart==0.0.20
wsproto
websockets
"""

# Utility functions
def color_text(text, color_code):
    return f"\033[{color_code}m{text}\033[0m"

def print_green(text):
    print(color_text(text, "32"))

def print_yellow(text):
    print(color_text(text, "33"))

def print_red(text):
    print(color_text(text, "31"))

def stop_service(service_name):
    try:
        print_yellow(f"Stopping the {service_name} service...")
        subprocess.check_call(["sudo", "systemctl", "stop", service_name])
        print_green(f"{service_name} service stopped successfully.")
    except subprocess.CalledProcessError as e:
        print_red(f"Failed to stop {service_name} service: {e}")

def check_setup_files():
    required_folders = ["waf-ghb", "waf-ghf", "waf-ghc"]
    required_file = "ghv.txt"
    items_in_directory = os.listdir(PROJECT_DIR)
    for folder in required_folders:
        if folder not in items_in_directory or not os.path.isdir(os.path.join(PROJECT_DIR, folder)):
            print_red(f"Missing folder: {folder}")
            return False
    if required_file not in items_in_directory or not os.path.isfile(os.path.join(PROJECT_DIR, required_file)):
        print_red(f"Missing file: {required_file}")
        return False
    with open(os.path.join(PROJECT_DIR, required_file), "r") as file:
        encoded_hash = file.read().strip()
    try:
        decoded_data = base64.b64decode(encoded_hash).decode()
    except Exception as e:
        print_red(f"Error decoding password: {e}")
        return False
    if decoded_data.lower() == "version":
        print_green("Version key verified!")
        return True
    return False

def check_python():
    try:
        subprocess.check_call([sys.executable, '--version'])
        print_green("Python is installed.")
    except subprocess.CalledProcessError:
        print_red("Python is not installed.")
        sys.exit(1)

def check_pip():
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "--version"])
        print_green("pip is installed.")
    except subprocess.CalledProcessError:
        print_red("pip is not installed.")
        sys.exit(1)

def check_apache():
    try:
        status = subprocess.run(["systemctl", "is-active", "apache2"], stdout=subprocess.PIPE, text=True).stdout.strip()
        if status == "active":
            print_green("Apache is running.")
        else:
            print_yellow("Apache is not running, starting it now...")
            subprocess.check_call(["sudo", "systemctl", "start", "apache2"])
            print_green("Apache started.")
    except subprocess.CalledProcessError:
        print_red("Failed to check Apache status.")
        sys.exit(1)

def check_mod_wsgi():
    try:
        result = subprocess.run(["/usr/sbin/apache2ctl", "-M"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if "wsgi_module" not in result.stdout:
            print_red("mod_wsgi module is not installed.")
            sys.exit(1)
        print_green("mod_wsgi module is installed.")
    except Exception as e:
        print_red(f"Error verifying mod_wsgi: {e}")
        sys.exit(1)

def find_free_port_in_range(start=62000, end=62999):
    for port in range(start, end + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(('127.0.0.1', port)) != 0:
                return port
    raise RuntimeError("No free port available.")

def get_server_ip():
    try:
        ip = subprocess.check_output("hostname -I", shell=True).decode().strip().split(' ')[0]
        return ip
    except subprocess.CalledProcessError:
        print_red("Error retrieving server IP.")
        sys.exit(1)

# Cleanup functions
def cleanup_apache_configs():
    print_yellow("Cleaning up old Apache configurations...")
    apache_config_paths = [
        os.path.join(APACHE_SITES_AVAILABLE, "waf-ghf_project.conf"),
        os.path.join(APACHE_SITES_AVAILABLE, "default-ssl.conf"),
    ]
    sites_enabled_path = "/etc/apache2/sites-enabled/"
    for symlink in os.listdir(sites_enabled_path):
        symlink_path = os.path.join(sites_enabled_path, symlink)
        if os.path.islink(symlink_path) and not os.path.exists(os.readlink(symlink_path)):
            os.remove(symlink_path)
            print_yellow(f"Removed dangling symlink: {symlink_path}")
    subprocess.check_call(["sudo", "systemctl", "reload", "apache2"])
    print_green("Apache configurations cleaned and reloaded.")

def cleanup_virtualenv():
    if os.path.exists(VENV_PATH):
        print_yellow(f"Removing old virtual environment at {VENV_PATH}...")
        shutil.rmtree(VENV_PATH)
        print_green("Old virtual environment removed.")

def cleanup_ssl_certificates():
    cert_file = os.path.join(SSL_DIR, "waf-gh-self-signed.crt")
    key_file = os.path.join(SSL_DIR, "waf-gh-self-signed.key")
    if os.path.exists(cert_file) and os.path.exists(key_file):
        print_yellow("Removing old SSL certificates...")
        os.remove(cert_file)
        os.remove(key_file)
        print_green("Old SSL certificates removed.")

# Setup functions
def create_virtualenv():
    if not os.path.exists(VENV_PATH):
        print_yellow("Creating virtual environment...")
        subprocess.check_call([sys.executable, "-m", "venv", VENV_PATH])
        print_green("Virtual environment created successfully.")

def create_requirements_file():
    requirements_path = os.path.join(PROJECT_DIR, "requirements.txt")
    if os.path.exists(requirements_path):
        os.remove(requirements_path)
    with open(requirements_path, "w") as f:
        f.write(REQUIREMENTS.strip())
    print_green("requirements.txt file created successfully.")

def install_requirements():
    print_yellow("Installing packages from requirements.txt...")
    pip_executable = os.path.join(VENV_PATH, "bin", "pip")
    requirements_file = os.path.join(PROJECT_DIR, "requirements.txt")
    subprocess.check_call([pip_executable, "install", "-r", requirements_file])
    print_green("Packages installed successfully.")

def create_ssl_certificate(ip_address):
    cert_file = os.path.join(SSL_DIR, "waf-gh-self-signed.crt")
    key_file = os.path.join(SSL_DIR, "waf-gh-self-signed.key")
    config_file = os.path.join(SSL_DIR, "openssl.cnf")
    os.makedirs(SSL_DIR, exist_ok=True)
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        print_yellow("Generating self-signed SSL certificate...")
        with open(config_file, "w") as f:
            f.write(f"""
[req]
default_bits       = 2048
default_keyfile    = privkey.pem
distinguished_name = req_distinguished_name
req_extensions     = v3_req

[req_distinguished_name]
C = US
ST = State
L = City
O = Company
CN = {ip_address}

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names HEART]
IP.1 = {ip_address}
            """)
        subprocess.check_call(["openssl", "genrsa", "-out", key_file, "2048"])
        subprocess.check_call([
            "openssl", "req", "-new", "-x509", "-key", key_file, "-out", cert_file,
            "-days", "365", "-config", config_file, "-nodes"
        ])
        subprocess.check_call(["sudo", "chown", "root:www-data", key_file, cert_file])
        subprocess.check_call(["sudo", "chmod", "640", key_file, cert_file])
        os.remove(config_file)
        print_green(f"SSL certificates generated: {cert_file}, {key_file}")
    return cert_file, key_file

def configure_config_files(ip_address):
    """Configure config.json for frontend with the server's IP and backend port."""
    config_dir = os.path.join(FRONTEND_DIR, "assets", "assets")
    config_file_path = os.path.join(config_dir, "config.json")
    os.makedirs(config_dir, exist_ok=True)
    print_yellow("Configuring config.json...")
    config_data = {
        "http_address": f"https://{ip_address}:{BACKEND_PORT}",
        "websocket_address": f"wss://{ip_address}:{BACKEND_PORT}/ws"
    }
    with open(config_file_path, "w") as f:
        json.dump(config_data, f, indent=4)
    print_green(f"config.json configured at {config_file_path}")

def configure_apache_frontend(desired_port, cert_file, key_file):
    apache_config_path = os.path.join(APACHE_SITES_AVAILABLE, "waf-ghf_project.conf")
    print_yellow("Configuring Apache frontend...")
    with open(apache_config_path, "w") as config_file:
        config_file.write(f"""
<VirtualHost *:{desired_port}>
    DocumentRoot {FRONTEND_DIR}
    <Directory {FRONTEND_DIR}>
        Options Indexes FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>

    SSLEngine on
    SSLCertificateFile {cert_file}
    SSLCertificateKeyFile {key_file}

    SSLProxyEngine on
    ProxyPass "/api" "https://{get_server_ip()}:{BACKEND_PORT}/api"
    ProxyPassReverse "/api" "https://{get_server_ip()}:{BACKEND_PORT}/api"
    ProxyPass "/ws" "wss://{get_server_ip()}:{BACKEND_PORT}/ws"
    ProxyPassReverse "/ws" "wss://{get_server_ip()}:{BACKEND_PORT}/ws"

    Header set Access-Control-Allow-Origin "*"
    Header set Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS"
    Header set Access-Control-Allow-Headers "Content-Type, X-Requested-With, Authorization"
</VirtualHost>
""")
    subprocess.check_call(["sudo", "a2ensite", "waf-ghf_project.conf"])
    subprocess.check_call(["sudo", "systemctl", "reload", "apache2"])
    print_green("Apache frontend configured.")

def create_backend_service(cert_file, key_file):
    service_path = "/etc/systemd/system/waf-ghb-backend.service"
    python_executable = os.path.join(VENV_PATH, "bin", "python3")
    print_yellow("Creating backend service...")
    with open(service_path, "w") as service_file:
        service_file.write(f"""
[Unit]
Description=WAF Backend Service
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory={BACKEND_DIR}
ExecStart={python_executable} -m uvicorn app:app --host 0.0.0.0 --port {BACKEND_PORT} --ssl-keyfile {key_file} --ssl-certfile {cert_file}
Environment=PATH={VENV_PATH}/bin:$PATH
Restart=on-failure

[Install]
WantedBy=multi-user.target
""")
    subprocess.check_call(["sudo", "systemctl", "daemon-reload"])
    subprocess.check_call(["sudo", "systemctl", "enable", "waf-ghb-backend"])
    subprocess.check_call(["sudo", "systemctl", "start", "waf-ghb-backend"])
    print_green("Backend service created and started.")

def remove_existing_nginx():
    print_yellow("Removing existing Nginx installation...")
    for path in ["/usr/local/nginx", "/etc/nginx", "/var/log/nginx", "/var/run/nginx"]:
        subprocess.run(["sudo", "rm", "-rf", path])
    subprocess.run(["sudo", "pkill", "-f", "nginx"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocess.run(["sudo", "rm", "-f", "/etc/systemd/system/nginx.service"])
    subprocess.run(["sudo", "systemctl", "stop", "nginx"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print_green("Existing Nginx removed.")

def install_nginx_dependencies():
    print_yellow("Installing Nginx dependencies...")
    subprocess.run(["sudo", "apt-get", "update"])
    subprocess.run(["sudo", "apt-get", "install", "-y", "build-essential", "libpcre3", "libpcre3-dev", "libssl-dev", "zlib1g-dev", "git"])

def install_nginx():
    print_yellow(f"Installing Nginx {NGINX_VERSION}...")
    subprocess.run(["wget", f"http://nginx.org/download/nginx-{NGINX_VERSION}.tar.gz"])
    subprocess.run(["tar", "-xzvf", f"nginx-{NGINX_VERSION}.tar.gz"])
    os.chdir(f"nginx-{NGINX_VERSION}")
    subprocess.run(["./configure", f"--prefix=/usr/local/nginx", "--add-dynamic-module=../ModSecurity-nginx"])
    subprocess.run(["make"])
    subprocess.run(["sudo", "make", "install"])
    os.chdir("..")

def install_modsecurity():
    print_yellow("Installing ModSecurity...")
    subprocess.run(["git", "clone", MODSEC_NGINX_REPO])
    os.chdir("ModSecurity-nginx")
    latest_tag = sorted(subprocess.check_output(["git", "tag"]).decode().strip().split("\n"), 
                       key=lambda s: list(map(int, s.strip("v").split("."))))[-1]
    subprocess.run(["git", "checkout", latest_tag])
    os.chdir(f"../nginx-{NGINX_VERSION}")
    subprocess.run(["./configure", f"--prefix=/usr/local/nginx", "--add-dynamic-module=../ModSecurity-nginx"])
    subprocess.run(["make"])
    subprocess.run(["sudo", "make", "install"])
    os.chdir("..")
    if os.path.exists("/usr/local/nginx/modules/ngx_http_modsecurity_module.so"):
        print_green("ModSecurity installed successfully.")
    else:
        print_red("ModSecurity installation failed.")
        sys.exit(1)

def install_owasp_crs():
    print_yellow("Installing OWASP CRS...")
    subprocess.run(["git", "clone", OWASP_CRS_REPO])
    os.chdir("coreruleset")
    tags = [tag for tag in subprocess.check_output(["git", "tag"]).decode().strip().split("\n") 
            if re.match(r"^v?\d+(\.\d+)+$", tag)]
    latest_tag = sorted(tags, key=lambda s: list(map(int, s.strip("v").split("."))))[-1]
    subprocess.run(["git", "checkout", latest_tag])
    subprocess.run(["sudo", "cp", "-r", "crs-setup.conf.example", NGINX_CONF_DIR])
    subprocess.run(["sudo", "cp", "-r", "rules/", "/usr/local/nginx/"])
    with open(os.path.join(NGINX_CONF_DIR, "modsec_includes.conf"), "a") as f:
        f.write("\nInclude /usr/local/nginx/rules/*.conf\n")
    os.chdir("..")
    print_green("OWASP CRS installed.")

def setup_modsecurity_config():
    print_yellow("Setting up ModSecurity config...")
    config_url = "https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/modsecurity.conf-recommended"
    config_path = os.path.join(NGINX_CONF_DIR, "modsecurity.conf")
    os.makedirs(NGINX_CONF_DIR, exist_ok=True)
    subprocess.run(["wget", "-O", "/tmp/modsecurity.conf", config_url])
    subprocess.run(["sudo", "mv", "/tmp/modsecurity.conf", config_path])
    subprocess.run(["sudo", "chmod", "644", config_path])
    with open(os.path.join(NGINX_CONF_DIR, "modsec_includes.conf"), "a") as f:
        f.write(f"\nInclude {config_path}\n")
    print_green("ModSecurity config setup complete.")

def setup_unicode_mapping():
    print_yellow("Setting up Unicode mapping...")
    unicode_url = "https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/unicode.mapping"
    mapping_path = os.path.join(NGINX_CONF_DIR, "unicode.mapping")
    subprocess.run(["wget", "-O", "/tmp/unicode.mapping", unicode_url])
    subprocess.run(["sudo", "mv", "/tmp/unicode.mapping", mapping_path])
    subprocess.run(["sudo", "chmod", "644", mapping_path])
    print_green("Unicode mapping setup complete.")

def configure_crs_setup():
    print_yellow("Configuring CRS setup...")
    crs_setup_example = os.path.join(NGINX_CONF_DIR, "crs-setup.conf.example")
    crs_setup_active = os.path.join(NGINX_CONF_DIR, "crs-setup.conf")
    subprocess.run(["sudo", "cp", crs_setup_example, crs_setup_active])
    with open(os.path.join(NGINX_CONF_DIR, "modsec_includes.conf"), "a") as f:
        f.write(f"\nInclude {crs_setup_active}\n")
    print_green("CRS setup configured.")

def setup_modsecurity_audit_log():
    print_yellow("Configuring ModSecurity audit log...")
    with open(os.path.join(NGINX_CONF_DIR, "modsec_includes.conf"), "a") as f:
        f.write("""
# ModSecurity Audit Log configuration
SecAuditEngine On
SecAuditLog /var/log/modsec_audit.log
SecAuditLogParts ABIJDEFHZ
SecAuditLogType Serial
""")
    print_green("Audit log configured.")

def write_nginx_conf(ip_address, apache_port, cert_file, key_file):
    nginx_conf_path = os.path.join(NGINX_CONF_DIR, "nginx.conf")
    print_yellow("Writing Nginx configuration...")
    with open(nginx_conf_path, "w") as f:
        f.write(f"""
load_module /usr/local/nginx/modules/ngx_http_modsecurity_module.so;

events {{
    worker_connections 1024;
}}

http {{
    server {{
        listen 443 ssl;
        server_name {ip_address};
        ssl_certificate {cert_file};
        ssl_certificate_key {key_file};
        modsecurity on;
        modsecurity_rules_file {NGINX_CONF_DIR}/modsec_includes.conf;
        location / {{
            proxy_pass http://{ip_address}:{apache_port};
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
        }}
    }}
}}
""")
    print_green("Nginx configuration written.")

def create_nginx_service():
    print_yellow("Creating Nginx service...")
    service_path = "/etc/systemd/system/nginx.service"
    with open(service_path, "w") as f:
        f.write(f"""
[Unit]
Description=NGINX with ModSecurity
After=network.target

[Service]
ExecStart={NGINX_SBIN}
ExecReload={NGINX_SBIN} -s reload
ExecStop={NGINX_SBIN} -s stop
PIDFile=/usr/local/nginx/logs/nginx.pid
Type=forking

[Install]
WantedBy=multi-user.target
""")
    subprocess.run(["sudo", "systemctl", "daemon-reload"])
    subprocess.run(["sudo", "systemctl", "enable", "nginx"])
    subprocess.run(["sudo", "systemctl", "start", "nginx"])
    print_green("Nginx service created and started.")

def setup_nginx(desired_port, ip_address, cert_file, key_file):
    original_dir = os.getcwd()
    os.chdir("/tmp")
    remove_existing_nginx()
    install_nginx_dependencies()
    install_nginx()
    install_modsecurity()
    install_owasp_crs()
    setup_modsecurity_config()
    setup_unicode_mapping()
    configure_crs_setup()
    setup_modsecurity_audit_log()
    write_nginx_conf(ip_address, desired_port, cert_file, key_file)
    create_nginx_service()
    os.chdir(original_dir)
    print_green("Nginx with ModSecurity setup completed.")

# Additional configuration functions
def update_ports_conf(desired_port):
    with open(APACHE_PORTS_CONF, 'r') as f:
        content = f.read()
    if f"Listen {desired_port}" not in content:
        print_yellow(f"Adding Listen directive for port {desired_port}...")
        with open(APACHE_PORTS_CONF, 'a') as f:
            f.write(f"\nListen {desired_port}\n")
        print_green(f"Port {desired_port} added.")
    subprocess.check_call(["sudo", "systemctl", "reload", "apache2"])

def adjust_permissions(path):
    print_yellow(f"Adjusting permissions for {path}...")
    subprocess.check_call(["sudo", "chmod", "-R", "755", path])
    subprocess.check_call(["sudo", "chown", "-R", "www-data:www-data", path])
    print_green("Permissions adjusted.")

def enable_apache_modules():
    print_yellow("Enabling Apache modules...")
    for mod in ["ssl", "proxy", "proxy_http", "proxy_wstunnel", "rewrite"]:
        subprocess.check_call(["sudo", "a2enmod", mod])
    subprocess.check_call(["sudo", "systemctl", "reload", "apache2"])
    subprocess.check_call(["sudo", "systemctl", "restart", "waf-ghb-backend"])
    print_green("Apache modules enabled and services restarted.")

def check_and_download_controller():
    app_name = "waf-interface"
    repo_url = "https://github.com/Waf-Interface/Cli-Controller"
    latest_url = subprocess.run(
        ["curl", "-s", f"{repo_url}/releases/latest", "-L", "-o", "/dev/null", "-w", "%{url_effective}"],
        capture_output=True, text=True
    ).stdout.strip()
    version = latest_url.split("/")[-1]
    download_url = f"{repo_url}/releases/download/{version}/{app_name}"
    if not os.path.exists(os.path.join(WAF_ROOT, app_name)):
        print_yellow(f"Downloading {app_name}...")
        subprocess.run(["wget", "-q", download_url, "-O", os.path.join(WAF_ROOT, app_name)])
        os.chmod(os.path.join(WAF_ROOT, app_name), 0o755)
        print_green(f"{app_name} downloaded to {WAF_ROOT}.")
    bashrc = os.path.expanduser("~/.bashrc")
    with open(bashrc, "a") as f:
        f.write(f"\nexport PATH=\"{WAF_ROOT}:$PATH\"\n")
    print_green("Controller setup complete. Run 'source ~/.bashrc' to update PATH.")

def prepare_ssl_certificates(key_file, cert_file):
    shutil.copy2(key_file, os.path.join(WAF_ROOT, "waf-gh-self-signed.key"))
    shutil.copy2(cert_file, os.path.join(WAF_ROOT, "waf-gh-self-signed.crt"))
    print_green(f"Certificates copied to {WAF_ROOT}.")

def install_prerequisites():
    print_yellow("Checking and installing prerequisites...")
    prerequisites = [
        "python3-pip", "apache2", "libapache2-mod-wsgi-py3", "build-essential",
        "openssl", "wget", "git", "curl"
    ]
    missing = []
    for pkg in prerequisites:
        result = subprocess.run(["dpkg", "-l", pkg], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            missing.append(pkg)
    if missing:
        print_yellow(f"Installing missing prerequisites: {', '.join(missing)}")
        subprocess.check_call(["sudo", "apt-get", "update"])
        subprocess.check_call(["sudo", "apt-get", "install", "-y"] + missing)
        print_green("All prerequisites installed successfully.")
    else:
        print_green("All prerequisites are already installed.")

def setup_project_root():
    """Set up the project root directory and move files into it."""
    if not os.path.exists(WAF_ROOT):
        print_yellow(f"Creating project root at {WAF_ROOT}...")
        os.makedirs(WAF_ROOT, exist_ok=True)
    current_dir = os.getcwd()
    for item in ["waf-ghb", "waf-ghf", "waf-ghc", "ghv.txt"]:
        src = os.path.join(current_dir, item)
        dest = os.path.join(WAF_ROOT, item)
        if os.path.exists(src) and not os.path.exists(dest):
            shutil.move(src, dest)
            print_green(f"Moved {item} to {dest}")
    adjust_permissions(WAF_ROOT)

def main():
    install_prerequisites()
    
    setup_project_root()  # Set up the project root first
    
    if not check_setup_files():
        print_red("Setup validation failed.")
        sys.exit(1)
    stop_service("waf-ghb-backend")
    
    check_python()
    check_pip()
    check_apache()
    check_mod_wsgi()
    
    cleanup_apache_configs()
    cleanup_virtualenv()
    cleanup_ssl_certificates()
    
    create_virtualenv()
    create_requirements_file()
    install_requirements()
    
    desired_port = find_free_port_in_range()
    ip_address = get_server_ip()
    cert_file, key_file = create_ssl_certificate(ip_address)
    
    configure_config_files(ip_address)  
    configure_apache_frontend(desired_port, cert_file, key_file)
    create_backend_service(cert_file, key_file)
    setup_nginx(desired_port, ip_address, cert_file, key_file)
    
    update_ports_conf(desired_port)
    enable_apache_modules()
    check_and_download_controller()
    prepare_ssl_certificates(key_file, cert_file)
    adjust_permissions(BACKEND_DIR)
    adjust_permissions(FRONTEND_DIR)
    
    print_green(f"Setup completed successfully! Access via: https://{ip_address}")

if __name__ == "__main__":
    main()
