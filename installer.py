#!/usr/bin/env python3

import os
import subprocess
import sys
import socket
import shutil
import py_compile
import socket
import base64

PROJECT_DIR = os.path.abspath(".")  
BACKEND_DIR = os.path.abspath("waf-ghb")
FRONTEND_DIR = os.path.abspath("waf-ghf")  
VENV_PATH = os.path.join(PROJECT_DIR, "venv")  

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
psutil 6.1.1
python-multipart==0.0.20
wsproto
websockets 
"""

def color_text(text, color_code):
    return f"\033[{color_code}m{text}\033[0m"

def print_green(text):
    print(color_text(text, "32"))

def print_yellow(text):
    print(color_text(text, "33"))

def print_red(text):
    print(color_text(text, "31"))

# def get_current_username():
#     return os.getlogin()

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
    current_directory = os.getcwd()
    items_in_directory = os.listdir(current_directory)
    print(f"Items in the directory: {items_in_directory}")
    for folder in required_folders:
        if folder not in items_in_directory or not os.path.isdir(folder):
            print(f"Missing folder: {folder}")
            return False
    if required_file not in items_in_directory or not os.path.isfile(required_file):
        print(f"Missing file: {required_file}")
        return False
    with open(required_file, "r") as file:
        encoded_hash = file.read().strip()
    try:
        decoded_data = base64.b64decode(encoded_hash).decode() 
    except Exception as e:
        print(f"Error decoding password: {e}")
        return False
    
    if decoded_data.lower() == "version":
        print("Version key verified!")
        return True
    else:
        print(f"Decrypted message does not match 'version': {decoded_data}")
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
        apache_status = subprocess.run(
            ["systemctl", "is-active", "apache2"], stdout=subprocess.PIPE, text=True
        ).stdout.strip()
        if apache_status == "active":
            print_green("Apache is running.")
        else:
            print_yellow("Apache is not running, starting it now...")
            subprocess.check_call(["sudo", "systemctl", "start", "apache2"])
            print_green("Apache started.")
    except subprocess.CalledProcessError:
        print_red("Failed to check Apache status. Ensure Apache is installed.")
        sys.exit(1)

def check_mod_wsgi():
    apachectl_path = "/usr/sbin/apache2ctl"
    if not os.path.exists(apachectl_path):
        print_red(f"{apachectl_path} not found. Ensure Apache utilities are installed.")
        sys.exit(1)

    try:
        result = subprocess.run([apachectl_path, "-M"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if "wsgi_module" not in result.stdout:
            print_red("mod_wsgi module for Apache is not installed.")
            sys.exit(1)
        else:
            print_green("mod_wsgi module is installed.")
    except Exception as e:
        print_red(f"Error verifying mod_wsgi: {e}")
        sys.exit(1)

def find_free_port_in_range(start=62000, end=62999):
    for port in range(start, end + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(('127.0.0.1', port)) != 0: 
                return port
    raise RuntimeError("No free port available in the specified range.")

def read_ac_txt():
    ac_txt_path = os.path.join(BACKEND_DIR, "ac.txt")
    config = {}

    ip_address = get_server_ip() 
    port = "6200"

    if os.path.exists(ac_txt_path):
        with open(ac_txt_path, 'r') as file:
            for line in file:
                parts = line.strip().split(":")
                if len(parts) == 2:
                    config[parts[0].strip()] = parts[1].strip()
    else:
        print_yellow(f"{ac_txt_path} not found. Creating a new one.")

    config['http'] = f"https://{ip_address}:{port}"
    config['websocket'] = f"wss://{ip_address}:{port}"

    with open(ac_txt_path, 'w') as file:
        for key, value in config.items():
            file.write(f"{key}: {value}\n")

    print_green("Configuration in ac.txt updated successfully.")
    return config

def update_frontend_config_js():
    ip_address = get_server_ip()  
    port = "6200"

    http_address = f"https://{ip_address}:{port}"
    websocket_address = f"wss://{ip_address}:{port}"

    apache_config_path = "/etc/apache2/sites-available/waf-ghf_project.conf"
    frontend_dir = None

    if not os.path.exists(apache_config_path):
        print_red(f"Apache configuration file {apache_config_path} not found.")
        sys.exit(1)

    with open(apache_config_path, 'r') as apache_config:
        for line in apache_config:
            if line.strip().startswith("DocumentRoot"):
                frontend_dir = line.split("DocumentRoot", 1)[1].strip()
                break

    if not frontend_dir or not os.path.exists(frontend_dir):
        print_red("Failed to locate frontend directory from Apache configuration.")
        sys.exit(1)

    config_js_path = os.path.join(frontend_dir, "assets", "assets", "config.json")
    if not os.path.exists(config_js_path):
        print_red(f"`config.json` not found at expected location: {config_js_path}.")
        sys.exit(1)

    print_yellow(f"Updating {config_js_path} with HTTP and WebSocket addresses...")

    try:
        with open(config_js_path, 'w') as config_file:
            config_file.write(f"""
{{
  "http_address": "{http_address}",
  "websocket_address": "{websocket_address}"
}}
""")
        print_green(f"Successfully updated {config_js_path} with HTTPS and WSS addresses.")
    except Exception as e:
        print_red(f"Error updating {config_js_path}: {e}")
        sys.exit(1)

def cleanup_apache_configs():
    print_yellow("Cleaning up old Apache configurations...")
    apache_config_paths = [
        "/etc/apache2/sites-available/waf-ghf_project.conf",
        "/etc/apache2/sites-available/waf-ghb_project.conf",
        "/etc/apache2/sites-available/default-ssl.conf",
    ]
            
    sites_enabled_path = "/etc/apache2/sites-enabled/"
    for symlink in os.listdir(sites_enabled_path):
        symlink_path = os.path.join(sites_enabled_path, symlink)
        if not os.path.exists(os.readlink(symlink_path)): 
            os.remove(symlink_path)
            print_yellow(f"Removed dangling symlink: {symlink_path}")

    subprocess.run(["sudo", "apache2ctl", "configtest"], check=True) 

    apache_status = subprocess.run(
        ["systemctl", "is-active", "apache2"], stdout=subprocess.PIPE, text=True
    ).stdout.strip()
    
    if apache_status != "active":
        print_yellow("Apache is not running, starting Apache now...")
        subprocess.check_call(["sudo", "systemctl", "start", "apache2"])
        print_green("Apache started.")
    
    subprocess.check_call(["sudo", "systemctl", "reload", "apache2"])
    print_green("Apache configurations cleaned and reloaded.")

def cleanup_virtualenv():
    if os.path.exists(VENV_PATH):
        print_yellow(f"Removing old virtual environment at {VENV_PATH}...")
        subprocess.check_call(["rm", "-rf", VENV_PATH])
        print_green("Old virtual environment removed.")

def cleanup_ssl_certificates():
    ssl_dir = "/etc/ssl/private"
    cert_file = os.path.join(ssl_dir, "waf-gh-self-signed.crt")
    key_file = os.path.join(ssl_dir, "waf-gh-self-signed.key")

    if os.path.exists(cert_file) and os.path.exists(key_file):
        print_yellow("Removing old SSL certificates...")
        os.remove(cert_file)
        os.remove(key_file)
        print_green("Old SSL certificates removed.")

def create_virtualenv():
    if not os.path.exists(VENV_PATH):
        print_yellow("Creating virtual environment...")
        subprocess.check_call([sys.executable, "-m", "venv", VENV_PATH])
        print_green("Virtual environment created successfully.")
    else:
        print_yellow("Virtual environment already exists.")

def create_requirements_file():
    requirements_path = os.path.join(PROJECT_DIR, "requirements.txt")

    if os.path.exists(requirements_path):
        print_yellow("Cleaning old requirements.txt file...")
        open(requirements_path, 'w').close()  
    with open(requirements_path, "w") as f:
        f.write(REQUIREMENTS.strip())
    print_green("requirements.txt file created successfully.")

def install_requirements():
    print_yellow("Installing packages from requirements.txt...")

    pip_executable = os.path.join(VENV_PATH, "bin", "pip")
    requirements_file = os.path.join(PROJECT_DIR, "requirements.txt")
    
    with open(requirements_file, "r") as file:
        content = file.read()
    corrected_content = content.replace("psutil 6.1.1", "psutil==6.1.1")
    
    if content != corrected_content:
        print_yellow("Correcting invalid psutil requirement in requirements.txt...")
        with open(requirements_file, "w") as file:
            file.write(corrected_content)
    
    try:
        subprocess.check_call([pip_executable, "install", "-r", requirements_file])
        print_green("Packages installed successfully.")
    except subprocess.CalledProcessError as e:
        print_red(f"Error installing packages: {e}")
        sys.exit(1)
   
def is_port_available(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        result = s.connect_ex(('0.0.0.0', port))
        return result != 0

import subprocess

def get_server_ip():
    try:
        ip = subprocess.check_output("hostname -I", shell=True).decode().strip().split(' ')[0]
        return ip
    except subprocess.CalledProcessError:
        print_red("Error retrieving the server IP address.")
        sys.exit(1)

def create_ssl_certificate(ip_address, ssl_dir="/etc/ssl/private"):
    cert_file = os.path.join(ssl_dir, "waf-gh-self-signed.crt")
    key_file = os.path.join(ssl_dir, "waf-gh-self-signed.key")

    os.makedirs(ssl_dir, exist_ok=True)

    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        try:
            print_yellow("Generating self-signed SSL certificate...")
            subprocess.check_call([
                "openssl", "genrsa", "-out", key_file, "2048"
            ])
            subprocess.check_call([
                "openssl", "req", "-new", "-x509", "-key", key_file, "-out", cert_file,
                "-days", "365", "-subj", f"/C=US/ST=State/L=City/O=Company/CN={ip_address}"
            ])
            subprocess.check_call(["sudo", "chmod", "600", key_file, cert_file])
            subprocess.check_call(["sudo", "chown", "root:root", key_file, cert_file])

            print_green(f"SSL certificates generated:\nKey: {key_file}\nCert: {cert_file}")
        except subprocess.CalledProcessError as e:
            print_red(f"Error creating SSL certificates: {e}")
            sys.exit(1)
    else:
        print_green("SSL certificates already exist.")
    
    return cert_file, key_file

def update_apache_config_file(config_path, content):
    if os.path.exists(config_path):
        backup_path = config_path + ".bak"
        shutil.copy(config_path, backup_path)
        print(f"Backup of {config_path} created as {backup_path}.")
    
    try:
        with open(config_path, 'w') as file:
            file.write(content)
        subprocess.check_call(["sudo", "a2ensite", os.path.basename(config_path)])
        subprocess.check_call(["sudo", "systemctl", "reload", "apache2"])
        print(f"Apache configuration updated and reloaded: {config_path}.")
    except Exception as e:
        print(f"Error updating Apache configuration: {e}")

def compile_backend_script(source_path, output_path):
    try:
        py_compile.compile(source_path, cfile=output_path)
        print(f"Compiled {source_path} successfully into {output_path}.")
    except Exception as e:
        print(f"Error compiling {source_path}: {e}")

def configure_apache_frontend(desired_port):
    config = read_ac_txt()
    frontend_http_address = config['http']
    frontend_websocket_address = config['websocket']
    
    ip_address = get_server_ip()

    cert_file, key_file = create_ssl_certificate(ip_address)

    apache_config_path = "/etc/apache2/sites-available/waf-ghf_project.conf"

    print_yellow("Creating Apache configuration file for frontend with SSL and backend proxy rules...")

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

    # CORS settings for frontend
    Header set Access-Control-Allow-Origin "*"
    Header set Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS"
    Header set Access-Control-Allow-Headers "Content-Type, X-Requested-With, Authorization"
    Header set Access-Control-Allow-Credentials "true"

    # Proxy WebSocket requests to the backend server
    ProxyPass "/ws" "wss://0.0.0.0:6200/ws"
    ProxyPassReverse "/ws" "wss://0.0.0.0:6200/ws"

    <Location />
        Require all granted
    </Location>
</VirtualHost>

""")

    print_green("Apache configuration file for frontend with SSL and backend proxy rules created successfully.")
    subprocess.check_call(["/usr/sbin/a2ensite", "waf-ghf_project.conf"])
    subprocess.check_call(["sudo", "systemctl", "reload", "apache2"])

    print_green(f"Frontend Apache site enabled successfully with SSL.\nAccessible via: https://{ip_address}:{desired_port}")

def configure_apache_backend():
    config = read_ac_txt()
    ip_address = get_server_ip() 
    backend_http_address = f"http://{ip_address}:{config['http'].split(':')[-1]}"
    
    backend_dir = os.path.abspath("waf-ghb")
    backend_config_path = "/etc/apache2/sites-available/waf-ghb_project.conf"

    if not os.path.exists(backend_dir):
        os.makedirs(backend_dir)
        print_green(f"Created backend directory: {backend_dir}")

    compiled_script = os.path.join(PROJECT_DIR, BACKEND_DIR, "main.pyc")
    backend_script_dest = os.path.join(backend_dir, "main.pyc")

    if os.path.exists(compiled_script):
        if compiled_script != backend_script_dest:
            shutil.copy(compiled_script, backend_script_dest)
            print_green(f"Copied {compiled_script} to {backend_script_dest}")
        else:
            print_yellow(f"{compiled_script} and {backend_script_dest} are the same file. Skipping copy.")
    else:
        print_red(f"Compiled script {compiled_script} not found. Backend setup cannot proceed.")

    print_yellow("Creating Apache configuration file for backend with CORS headers...")

    with open(backend_config_path, "w") as config_file:
        config_file.write(f"""
<VirtualHost *:{config['http'].split(':')[-1]}>

    DocumentRoot {backend_dir}
    <Directory {backend_dir}>
        Options Indexes FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>

    # CORS headers for backend
    Header set Access-Control-Allow-Origin "*"
    Header set Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS"
    Header set Access-Control-Allow-Headers "Content-Type, X-Requested-With, Authorization"
    Header set Access-Control-Allow-Credentials "true"

    <Location />
        Require all granted
    </Location>
</VirtualHost>
        """)

    print_green("Apache configuration file for backend created successfully with CORS headers.")
    subprocess.check_call(["/usr/sbin/a2ensite", "waf-ghb_project.conf"])
    subprocess.check_call(["sudo", "systemctl", "reload", "apache2"])


def create_backend_service_and_socket(socket_path, config):
    service_path = "/etc/systemd/system/waf-ghb-backend.service"
    username = os.getenv("USER") 

    print(f"Running as user: {username}") 

    try:
        if not os.path.isdir("/etc/systemd/system/"):
            raise FileNotFoundError("/etc/systemd/system/ directory does not exist.")
        
        venv_path = f"/home/{username}/waf-interface/venv"  
        python_executable = os.path.join(venv_path, "bin", "python3")
        uvicorn_executable = os.path.join(venv_path, "bin", "uvicorn")

        print(f"Checking python executable: {python_executable}")
        print(f"Checking uvicorn executable: {uvicorn_executable}")
        
        if not os.path.exists(python_executable) or not os.path.exists(uvicorn_executable):
            raise FileNotFoundError(f"Virtual environment or uvicorn not found at {venv_path}")

        temp_service_path = "./waf-ghb-backend.service"
        with open(temp_service_path, "w") as service_file:
            service_file.write(f"""
[Unit]
Description=WAF-INTERFACE BACKEND SERVICE
After=network.target

[Service]
# Explicitly use the Python from the virtual environment and uvicorn to run the backend
ExecStart={python_executable} -m uvicorn waf-ghb.main:app --host 0.0.0.0 --port 6200 --ssl-keyfile /etc/ssl/private/waf-gh-self-signed.key --ssl-certfile /etc/ssl/private/waf-gh-self-signed.crt
Environment=PATH={venv_path}/bin:$PATH
WorkingDirectory=/home/{username}/waf-interface
Restart=on-failure

[Install]
WantedBy=multi-user.target
                  """)

        print(f"Temporary service file created at {temp_service_path}")

        shutil.move(temp_service_path, service_path)
        
        subprocess.check_call(["sudo", "systemctl", "daemon-reload"])

        print("Systemd service and socket activation configured and started for backend.")

    except Exception as e:
        print(f"Error occurred: {e}")
        raise

def update_ports_conf(desired_port):
    apache_ports_conf = "/etc/apache2/ports.conf"

    with open(apache_ports_conf, 'r') as f:
        ports_conf_content = f.read()

    if f"Listen {desired_port}" not in ports_conf_content:
        print_yellow(f"Adding Listen directive for port {desired_port} in {apache_ports_conf}...")
        with open(apache_ports_conf, 'a') as f:
            f.write(f"\nListen {desired_port}\n")
        print_green(f"Port {desired_port} added to {apache_ports_conf}.")
    else:
        print_green(f"Port {desired_port} is already listed in {apache_ports_conf}. No changes needed.")

    subprocess.check_call(["sudo", "systemctl", "reload", "apache2"])
    print_green("Apache reloaded successfully after updating ports.conf.")

def adjust_permissions(base_path):
    try:
        subprocess.check_call(["sudo", "chmod", "o+x", os.path.dirname(base_path)])
        subprocess.check_call(["sudo", "chmod", "-R", "755", base_path])
        subprocess.check_call(["sudo", "chown", "-R", "www-data:www-data", base_path])
        print("Permissions adjusted successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to adjust permissions: {e}")

def enable_apache_modules():
    print_yellow("Enabling required Apache modules...")
    subprocess.check_call(["sudo", "a2enmod", "ssl"])
    subprocess.check_call(["sudo", "a2enmod", "proxy"])
    subprocess.check_call(["sudo", "a2enmod", "proxy_http"])
    subprocess.check_call(["sudo", "a2enmod", "proxy_fcgi"])
    subprocess.check_call(["sudo", "a2enmod", "rewrite"])
    subprocess.check_call(["sudo", "systemctl", "reload", "apache2"])
    subprocess.check_call(["sudo", "systemctl", "restart", "waf-ghb-backend.service"])

    print_green("Required Apache modules enabled and Apache reloaded.")


def check_and_download_controller():
    app_name = "waf-interface"
    repo_url = "https://github.com/Waf-Interface/Cli-Controller"
    try:
        print_yellow("Fetching the latest release information...")
        result = subprocess.run(
            ["curl", "-s", f"{repo_url}/releases/latest", "-L", "-o", "/dev/null", "-w", "%{url_effective}"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print_red("Failed to fetch the latest release URL. Ensure `curl` is installed and accessible.")
            return

        latest_url = result.stdout.strip()
        if "/releases/latest" in latest_url:
            print("Failed to resolve the latest release URL.")
            return
        version = latest_url.split("/")[-1]
        download_url = f"{repo_url}/releases/download/{version}/{app_name}"

        print(f"Resolved latest release download URL: {download_url}")

    except Exception as e:
        print_red(f"An error occurred while fetching the release information: {e}")
        return
    if not os.path.exists(app_name):
        print_yellow(f"{app_name} not found in the current folder. Downloading...")
        try:
            subprocess.run(["wget", "-q", download_url, "-O", app_name], check=True)
            os.chmod(app_name, os.stat(app_name).st_mode | 0o111)
            print(f"{app_name} downloaded and made executable.")
        except subprocess.CalledProcessError:
            print_red(f"Failed to download {app_name}. Please check the URL or your internet connection.")
            return
    else:
        print(f"{app_name} is already available in the current folder.")
    current_path = os.getcwd()
    if current_path not in os.environ["PATH"]:
        os.environ["PATH"] += os.pathsep + current_path
        print(f"Added {current_path} to PATH (this is temporary, for the current session).")
    else:
        print("Verification successful: The app is already in the PATH.")
    bashrc_file = os.path.expanduser("~/.bashrc")
    if not os.path.exists(bashrc_file):
        print_red(f"{bashrc_file} not found. Cannot update the PATH permanently.")
        return

    with open(bashrc_file, "a") as f:
        f.write(f"\n# Adding {current_path} to PATH\n")
        f.write(f'export PATH="{current_path}:$PATH"\n')

    print_green(f"Added {current_path} to PATH in {bashrc_file}. You need to restart your terminal or run 'source ~/.bashrc' for the change to take effect.")


def main():
    # Step 0: 
    if not check_setup_files():
        print("Setup validation failed. Please ensure all required files and folders are present.")
        return  
    stop_service("waf-ghb-backend")

    # Step 1:
    check_python()
    check_pip()
    check_apache()
    check_mod_wsgi()

    # Step 2:
    cleanup_apache_configs()
    cleanup_virtualenv()
    cleanup_ssl_certificates()

    # Step 3:
    create_virtualenv()
    create_requirements_file()
    install_requirements()

    # Step 4:
    desired_port = find_free_port_in_range()

    # Step 5:
    ip_address = get_server_ip()
    cert_file, key_file = create_ssl_certificate(ip_address)

    # Step 6: 
    read_ac_txt()

    # Step 7:
    configure_apache_frontend(desired_port)
    configure_apache_backend()

    # Step 8: 
    socket_path = f"/run/waf-ghb-backend-{desired_port}.sock"
    config = read_ac_txt()
    update_ports_conf(desired_port)
    update_frontend_config_js()
    create_backend_service_and_socket(socket_path, config)

    # Step 9:
    enable_apache_modules()

    # Step 10:
    check_and_download_controller()

    # Step 11:
    adjust_permissions(BACKEND_DIR)
    adjust_permissions(FRONTEND_DIR)

    print_green("Setup completed successfully!")

  
if __name__ == "__main__":
    main()
