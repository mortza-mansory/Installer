#!/usr/bin/env python3

import os
import subprocess
import sys
import shutil
import json
import socket
from pathlib import Path
from time import sleep
from rich.console import Console
from rich.progress import (
    Progress,
    BarColumn,
    TextColumn,
    TimeRemainingColumn,
    SpinnerColumn,
)
from rich.panel import Panel
from rich.style import Style

console = Console()
WAF_ROOT = "/opt/waf_interface"
BACKEND_DIR = f"{WAF_ROOT}/waf-ghb"
FRONTEND_DIR = f"{WAF_ROOT}/waf-ghf"
VENV_PATH = f"{BACKEND_DIR}/venv"
SSL_DIR = "/etc/waf-ssl"
BACKEND_PORT = 8081
SERVICE_NAME = "waf-backend"
NGINX_VERSION = "1.23.0"
MODSECURITY_NGINX_REPO = "https://github.com/owasp-modsecurity/ModSecurity-nginx.git"
OWASP_CRS_REPO = "https://github.com/coreruleset/coreruleset.git"
SCRIPT_DIR = Path(__file__).parent.absolute()

REQUIREMENTS = [
    "fastapi==0.115.12",
    "uvicorn==0.32.1",
    "python-multipart==0.0.20",
    "psutil==6.1.1",
    "websockets",
    "sqlalchemy==2.0.40",
    "pymysql==1.1.0",
    "python-jose==3.3.0",
    "passlib==1.7.4",
    "pydantic==2.11.2",
    "starlette==0.41.3",
    "alembic==1.13.1",
    "sqlalchemy-utils==0.41.1",
    "PyJWT==2.10.1",
    "cryptography==44.0.2",
    "python-dotenv==0.20.0",
]

class InstallerProgress:

    _instance = None
    def __init__(self):
        self.progress = Progress(
            SpinnerColumn("dots"),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=None),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeRemainingColumn(),
            console=console,
            expand=True
        )
        
    def __enter__(self):
        self.progress.__enter__()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.progress.__exit__(exc_type, exc_val, exc_tb)
        
    def add_task(self, description, total=100):
        return self.progress.add_task(description, total=total)
        
    def update(self, task_id, **kwargs):
        self.progress.update(task_id, **kwargs)
        
    def advance(self, task_id, advance=1):
        self.progress.advance(task_id, advance)

    def __new__(cls):
        if not cls._instance:
            cls._instance = Progress(
                SpinnerColumn("dots"),
                TextColumn("[bold blue]{task.description}"),
                BarColumn(bar_width=None),
                "[progress.percentage]{task.percentage:>3.0f}%",
                TimeRemainingColumn(),
                console=console,
                expand=True
            )
        return cls._instance
def run(cmd, success_msg=None, error_msg=None, critical=True):
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            check=True,
            executable="/bin/bash",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        if success_msg:
            console.print(f"  [green]✓[/green] {success_msg}")
        return result
    except subprocess.CalledProcessError as e:
        console.print(f"\n[bold red]✗ Error in:[/bold red] {cmd}")
        console.print(f"[red]{e.stderr.decode().strip()}[/red]")
        if error_msg:
            console.print(f"[bold yellow]{error_msg}[/bold yellow]")
        if critical:
            sys.exit(1)
        return None

def clean_installation():
    console.print(Panel("[bold yellow]Cleaning previous installations...[/bold yellow]", style="yellow"))
    steps = [
        ("Stopping services", "sudo systemctl stop apache2 nginx waf-backend || true"),
        ("Removing directories", f"sudo rm -rf {WAF_ROOT} /etc/waf-ssl /usr/local/nginx /etc/nginx {VENV_PATH}"),
        ("Cleaning temp files", "sudo rm -rf /tmp/waf-installer"),
        ("Purging packages", "sudo apt-get remove -y --purge nginx nginx-common libnginx-mod*"),
        ("Cleaning Apache config", "sudo rm -f /etc/apache2/ports.conf /etc/apache2/sites-enabled/*"),  # NEW
    ]

    progress = InstallerProgress()
    task = progress.add_task("[cyan]Cleaning...", total=len(steps))
    for desc, cmd in steps:
        progress.update(task, description=f"[cyan]{desc}")
        run(cmd)
        progress.advance(task)
        sleep(0.1)

def verify_environment():
    required_dirs = ["waf-ghb", "waf-ghf", "waf-ghc"]
    missing = [d for d in required_dirs if not (SCRIPT_DIR / d).exists()]
    
    if missing:
        console.print(
            f"[bold red]Missing directories in {SCRIPT_DIR}:[/]\n"
            f"{', '.join(missing)}\n"
            f"[yellow]Clone required repositories to installer directory[/yellow]"
        )
        sys.exit(1)

def install_dependencies():
    console.print(Panel("[bold cyan]Installing system dependencies...[/bold cyan]", style="cyan"))
    steps = [
        ("Updating packages", "sudo apt-get update -y"),
        ("Installing requirements", "sudo apt-get install -y build-essential libpcre3 libpcre3-dev "
"zlib1g-dev libssl-dev apache2 apache2-dev python3-venv git libcap2-bin python3-venv git libcap2-bin"),
    ]
    
    with InstallerProgress() as progress:
        task = progress.add_task("[cyan]Processing...", total=len(steps))
        for desc, cmd in steps:
            progress.update(task, description=f"[cyan]{desc}")
            run(cmd)
            progress.advance(task)
            sleep(0.1)

def build_nginx():
    console.print(Panel("[bold cyan]Building Nginx with ModSecurity...[/bold cyan]", style="cyan"))
    temp_dir = Path("/tmp/waf-installer")
    temp_dir.mkdir(exist_ok=True)
    os.chdir(temp_dir)

    run("rm -rf nginx-* ModSecurity-nginx", critical=False)

    steps = [
        ("Downloading Nginx", f"wget -q http://nginx.org/download/nginx-{NGINX_VERSION}.tar.gz"),
        ("Extracting source", f"tar -xzf nginx-{NGINX_VERSION}.tar.gz"),
        ("Cloning ModSecurity", f"git clone --depth 1 {MODSECURITY_NGINX_REPO}"),
        ("Configuring build", f"./configure --prefix=/usr/local/nginx --add-dynamic-module=../ModSecurity-nginx "
         "--with-http_ssl_module --with-http_realip_module"),
        ("Compiling", "make -j$(nproc)"),
        ("Installing", "sudo make install"),
    ]

    with InstallerProgress() as progress:
        task = progress.add_task("[cyan]Building...", total=len(steps))
        for desc, cmd in steps:
            progress.update(task, description=f"[cyan]{desc}")
            
            if "configure" in cmd:
                os.chdir(temp_dir / f"nginx-{NGINX_VERSION}")
            
            run(cmd, error_msg="Retrying with fresh download...", critical=False)
            progress.advance(task)
            sleep(0.3)

def install_modsecurity_crs():
    console.print(Panel("[bold cyan]Configuring Security Rules...[/bold cyan]", style="cyan"))
    temp_dir = Path("/tmp/waf-installer")
    os.chdir(temp_dir)
    
    run("rm -rf coreruleset", critical=False)

    steps = [
        ("Cloning CRS", f"git clone --depth 1 {OWASP_CRS_REPO}"),
        ("Creating directories", "sudo mkdir -p /usr/local/nginx/rules"),
        ("Copying rules", "sudo cp -r coreruleset/rules/* /usr/local/nginx/rules/"),
        ("Configuring ModSecurity", configure_modsecurity),
    ]

    with InstallerProgress() as progress:
        task = progress.add_task("[cyan]Configuring...", total=len(steps))
        for desc, cmd in steps:
            progress.update(task, description=f"[cyan]{desc}")
            if callable(cmd):
                cmd()
            else:
                run(cmd)
            progress.advance(task)
            sleep(0.3)

def configure_modsecurity():
    modsec_conf = """SecRuleEngine On
SecAuditEngine RelevantOnly
SecAuditLog /var/log/modsec_audit.log
SecDebugLog /var/log/modsec_debug.log
SecDebugLogLevel 0
SecAuditLogParts ABIFHZ
SecAuditLogType Serial
SecArgumentSeparator &
SecCookieFormat 0
SecUnicodeMapFile unicode.mapping 20127
SecStatusEngine Off

Include /usr/local/nginx/rules/*.conf
"""
    with open("/tmp/modsec.conf", "w") as f:
        f.write(modsec_conf)
    run("sudo mv /tmp/modsec.conf /usr/local/nginx/conf/",
       success_msg="Created ModSecurity configuration")

def setup_project():
    console.print(Panel("[bold cyan]Setting up WAF project...[/bold cyan]", style="cyan"))
    try:
        verify_environment()
        steps = [
            ("Creating directories", f"sudo mkdir -p {WAF_ROOT} && sudo chown $USER:$USER {WAF_ROOT}"),
            ("Copying backend", f"cp -r {SCRIPT_DIR}/waf-ghb {BACKEND_DIR}"),
            ("Copying frontend", f"cp -r {SCRIPT_DIR}/waf-ghf {FRONTEND_DIR}"),
            ("Copying controller", f"cp -r {SCRIPT_DIR}/waf-ghc {WAF_ROOT}/waf-ghc"),
            ("Updating frontend config", (update_frontend_config, "✓ Frontend config updated")), 
            ("Setting permissions", f"sudo chown -R www-data:www-data {WAF_ROOT}"),
        ]

        with InstallerProgress() as progress:
            task = progress.add_task("[cyan]Setting up...", total=len(steps))
            for desc, cmd in steps:
                progress.update(task, description=f"[cyan]{desc}")
                if isinstance(cmd, tuple):  
                    func, success_msg = cmd
                    try:
                        func()
                        console.print(f"  [green]{success_msg}[/green]")
                    except Exception as e:
                        raise e
                elif "cp" in cmd:
                    src = cmd.split()[-2]
                    dst = cmd.split()[-1]
                    if os.path.exists(dst):
                        shutil.rmtree(dst)
                    shutil.copytree(src, dst)
                else:
                    run(cmd)
                progress.advance(task)
                sleep(0.3)
    except Exception as e:
        console.print(f"[bold red]Project setup failed: {str(e)}[/bold red]")
        sys.exit(1)

def setup_python_env():
    console.print(Panel("[bold cyan]Configuring Python environment...[/bold cyan]", style="cyan"))
    steps = [
        ("Creating venv", f"sudo -u www-data python3 -m venv {VENV_PATH} --clear"),
        ("Installing packages", f"sudo -u www-data {VENV_PATH}/bin/pip install --no-cache-dir {' '.join(REQUIREMENTS)}"),
    ]

    with InstallerProgress() as progress:
        task = progress.add_task("[cyan]Configuring...", total=len(steps))
        for desc, cmd in steps:
            progress.update(task, description=f"[cyan]{desc}")
            run(cmd)
            progress.advance(task)
            sleep(0.3)

def configure_services(ip):
    nginx_service = f"""[Unit]
Description=NGINX with ModSecurity
After=network.target

[Service]
Type=forking
PIDFile=/usr/local/nginx/logs/nginx.pid
ExecStartPre=/bin/sh -c 'mkdir -p /usr/local/nginx/logs && chown www-data:www-data /usr/local/nginx/logs'
ExecStartPre=/usr/local/nginx/sbin/nginx -t
ExecStart=/usr/local/nginx/sbin/nginx
ExecReload=/usr/local/nginx/sbin/nginx -s reload
ExecStop=/usr/local/nginx/sbin/nginx -s quit
TimeoutStartSec=300
TimeoutStopSec=5
Restart=on-failure
RestartSec=5s
Environment="NGINX_CONF_FILE=/usr/local/nginx/conf/nginx.conf"
Environment="NGINX_ERROR_LOG=/var/log/nginx/error.log"
User=www-data
Group=www-data
RuntimeDirectory=nginx
RuntimeDirectoryMode=0750

[Install]
WantedBy=multi-user.target
"""
    with open("/tmp/nginx.service", "w") as f:
        f.write(nginx_service)

    steps = [
        ("Generating SSL", (
        f"sudo mkdir -p {SSL_DIR} && "
        f"sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 "
        f"-subj '/CN=waf-server' -addext 'subjectAltName = IP:{ip}, IP:127.0.0.1, DNS:localhost' "
        f"-keyout {SSL_DIR}/waf.key -out {SSL_DIR}/waf.crt && "
        f"sudo chown www-data:www-data {SSL_DIR}/* && "
        f"sudo chmod 640 {SSL_DIR}/*"
        )),
        ("Configuring NGINX service", "sudo mv /tmp/nginx.service /etc/systemd/system/nginx.service"),
        ("Creating directories", (
            f"sudo mkdir -p /usr/local/nginx/logs /var/log/nginx /run/nginx {SSL_DIR} && "  
            "sudo chown -R www-data:www-data /usr/local/nginx /var/log/nginx /run/nginx {SSL_DIR} && "  
            "sudo chmod 0750 /run/nginx"
        ).format(SSL_DIR=SSL_DIR)), 
        ("Configuring Nginx", configure_nginx_and_security),
        ("Configuring Apache", configure_apache),
        ("Setting Nginx capabilities", "sudo setcap 'cap_net_bind_service=+ep' /usr/local/nginx/sbin/nginx"), 
        ("Reloading systemd", "sudo systemctl daemon-reload"),
        ("Validating Nginx config", "sudo -u www-data /usr/local/nginx/sbin/nginx -t"),
("Creating backend service", (
    f'''echo "[Unit]
Description=WAF Backend
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory={BACKEND_DIR}
Environment="PATH={VENV_PATH}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStartPre=/bin/sh -c 'fuser -k {BACKEND_PORT}/tcp || true'
ExecStart={VENV_PATH}/bin/python3 -m uvicorn app:app --host 0.0.0.0 --port {BACKEND_PORT} --ssl-keyfile {SSL_DIR}/waf.key --ssl-certfile {SSL_DIR}/waf.crt --proxy-headers
Restart=on-failure
RestartSec=5
KillMode=process

[Install]
WantedBy=multi-user.target" | sudo tee /etc/systemd/system/{SERVICE_NAME}.service''',
    "✓ Backend service configured"
)),
                ("Enabling backend", f"sudo systemctl enable --now {SERVICE_NAME}"),
        ("Reloading systemd", "sudo systemctl daemon-reload"),
        ("Starting services", (
            "sudo systemctl restart apache2 && "
            "sudo systemctl stop nginx && "
            "sudo systemctl start nginx && "
            "sleep 5 && "
            "sudo systemctl is-active nginx || (journalctl -u nginx --since '1 min ago'; false)"
        )),
    ]

    with InstallerProgress() as progress:
        task = progress.add_task("[cyan]Configuring...", total=len(steps))
        for desc, cmd in steps:
            progress.update(task, description=f"[cyan]{desc}")
            try:
                if callable(cmd):
                    cmd(ip)
                else:
                    run(cmd)
            except Exception as e:
                console.print(f"\n[bold red]✗ Critical error in step: {desc}[/bold red]")
                console.print(f"[yellow]Check service status with:[/yellow]")
                console.print(f"systemctl status nginx.service")
                console.print(f"journalctl -xe -u nginx.service")
                console.print(f"nginx config test: sudo /usr/local/nginx/sbin/nginx -t")
                sys.exit(1)
            progress.advance(task)
            sleep(0.3)

def configure_nginx_and_security(ip):
    console.print(Panel("[bold cyan]Configuring NGINX and Security...[/bold cyan]", style="cyan"))
    
    config_url = "https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/modsecurity.conf-recommended"
    config_path = "/usr/local/nginx/conf/modsecurity.conf"
    
    try:
        os.makedirs("/usr/local/nginx/conf", exist_ok=True)
        
        console.print("Downloading modsecurity.conf-recommended...")
        run(f"wget -O /tmp/modsecurity.conf-recommended {config_url}")
        
        console.print("Moving to correct location...")
        run(f"sudo mv /tmp/modsecurity.conf-recommended {config_path}")
        
        run(f"sudo chmod 644 {config_path}")
        
        includes_path = "/usr/local/nginx/conf/modsec_includes.conf"
        with open(includes_path, "a") as f:
            f.write("\nInclude /usr/local/nginx/conf/modsecurity.conf\n")
        
        console.print("[green]ModSecurity configuration file setup complete![/green]")
        
    except Exception as e:
        console.print(f"[red]Error setting up ModSecurity config: {str(e)}[/red]")
        sys.exit(1)

    unicode_url = "https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/49495f1925a14f74f93cb0ef01172e5abc3e4c55/unicode.mapping"
    mapping_path = "/usr/local/nginx/conf/unicode.mapping"
    
    try:
        console.print("Downloading unicode.mapping...")
        run(f"wget -O /tmp/unicode.mapping {unicode_url}")
        
        console.print("Moving to correct location...")
        run(f"sudo mv /tmp/unicode.mapping {mapping_path}")
        
        run(f"sudo chmod 644 {mapping_path}")
        
        console.print("[green]Unicode mapping file setup complete![/green]")
        
    except Exception as e:
        console.print(f"[red]Error setting up Unicode mapping file: {str(e)}[/red]")
        sys.exit(1)

    console.print(Panel("[bold yellow]Configuring CRS setup file...[/bold yellow]", style="yellow"))
    
    try:
        crs_setup_example = "/usr/local/nginx/conf/crs-setup.conf.example"
        crs_setup_active = "/usr/local/nginx/conf/crs-setup.conf"
        crs_setup_url = "https://raw.githubusercontent.com/coreruleset/coreruleset/main/crs-setup.conf.example"
        
        if not os.path.exists(crs_setup_example):
            console.print("crs-setup.conf.example not found, downloading from GitHub...")
            run(f"sudo wget -O {crs_setup_example} {crs_setup_url}")
            console.print("[green]Successfully downloaded crs-setup.conf.example[/green]")
        
        if os.path.exists(crs_setup_example):
            run(f"sudo cp {crs_setup_example} {crs_setup_active}")
            console.print("[green]Copied crs-setup.conf.example to crs-setup.conf[/green]")
        else:
            console.print("[red]Failed to obtain crs-setup.conf.example[/red]")
            sys.exit(1)
        
        modsec_includes_path = "/usr/local/nginx/conf/modsec_includes.conf"
        include_line = "Include /usr/local/nginx/conf/crs-setup.conf\n"
        
        if os.path.exists(modsec_includes_path):
            with open(modsec_includes_path, 'r') as f:
                if include_line in f.read():
                    console.print("[yellow]CRS setup already included in modsec_includes.conf[/yellow]")
                    return
        
        with open(modsec_includes_path, 'a') as f:
            f.write(include_line)
        
        console.print("[green]Added CRS setup include to modsec_includes.conf[/green]")
        
    except Exception as e:
        console.print(f"[red]Error configuring CRS setup: {str(e)}[/red]")
        sys.exit(1)

    nginx_conf = f"""load_module /usr/local/nginx/modules/ngx_http_modsecurity_module.so;

# PID Configuration
pid /usr/local/nginx/logs/nginx.pid;

events {{
    worker_connections 1024;
}}

http {{
    modsecurity on;
    modsecurity_rules_file /usr/local/nginx/conf/modsec_includes.conf;
    
    # Error Log Configuration
    error_log /var/log/nginx/error.log warn;
    
    server {{
        listen 80;
        listen 443 ssl;
        server_name {ip};
        
        ssl_certificate /etc/waf-ssl/waf.crt;
        ssl_certificate_key /etc/waf-ssl/waf.key;
        
        location / {{
            proxy_pass http://127.0.0.1:8080;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }}
         location /api/ {{
            proxy_pass https://127.0.0.1:{BACKEND_PORT};
            proxy_ssl_verify off;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }}
    }}
}}"""
    with open("/tmp/nginx.conf", "w") as f:
        f.write(nginx_conf)
    
    run("sudo mv /tmp/nginx.conf /usr/local/nginx/conf/nginx.conf",
       success_msg="Nginx configuration applied")
    
    console.print("[green]NGINX and security configurations completed successfully![/green]")
    
def configure_apache(ip):
    steps = [
        ("Configuring ports", 
            ("echo 'Listen 8080' | sudo tee /etc/apache2/ports.conf",
             "✓ Apache ports configured")),
        ("Creating virtualhost", 
            (f'''echo '<VirtualHost *:8080>
    DocumentRoot {FRONTEND_DIR}
    <Directory {FRONTEND_DIR}>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>' | sudo tee /etc/apache2/sites-available/waf.conf''',
             "✓ Apache virtualhost configured")),
        ("Disabling default site", 
            ("sudo a2dissite 000-default.conf", 
             "✓ Default site disabled")),
        ("Enabling WAF site", 
            ("sudo a2ensite waf.conf", 
             "✓ WAF site enabled"))
    ]
    
    for desc, (cmd, success_msg) in steps:
        run(cmd, success_msg=success_msg)

def update_frontend_config():
    """Update frontend configuration with correct URLs"""
    ip = socket.gethostbyname(socket.gethostname())
    config_path = Path(FRONTEND_DIR) / "assets" / "assets" / "config.json" 
    
    try:
        with open(config_path, "r+") as f:
            config = json.load(f)
            config["http_address"] = f"https://{ip}:{BACKEND_PORT}"
            config["websocket_address"] = f"wss://{ip}:{BACKEND_PORT}/ws"
            f.seek(0)
            json.dump(config, f, indent=2)
            f.truncate()
    except Exception as e:
        console.print(f"[red]Frontend config update failed: {str(e)}[/red]")
        sys.exit(1)
def finalize_installation(ip):
    console.print(Panel.fit(
        "[bold green] Installation Complete! 🎉[/bold green]",
        border_style=Style(color="green"),
        padding=(1, 2)
    ))
    console.print(f"\n🔐 [bold]Access the WAF interface:[/] [cyan underline]https://{ip}[/]")
    console.print(f"⚙️  [bold]Backend API:[/] [cyan underline]https://{ip}:{BACKEND_PORT}[/]")
    console.print("\n💡 [yellow]Run [bold]waf-interface --user-add[/] to create admin accounts[/]")

def main():
    console.clear()
    console.print(Panel.fit(
        "[bold blue] WAF Installation Wizard [/bold blue]",
        border_style=Style(color="blue", bold=True)),
        justify="center"
    )

    try:
        progress = InstallerProgress()
        with progress:
            os.chdir(SCRIPT_DIR)
            ip = socket.gethostbyname(socket.gethostname())

            installation_steps = [
                (verify_environment, "Verifying environment"),
                (clean_installation, "Cleaning system"),
                (install_dependencies, "Installing dependencies"),
                (build_nginx, "Building Nginx"),
                (install_modsecurity_crs, "Configuring security"),
                (setup_project, "Setting up project"),
                (setup_python_env, "Configuring Python"),
                (lambda: configure_services(ip), "Configuring services"),
            ]

            main_task = progress.add_task(
                "[cyan]Main Installation Progress[/cyan]",
                total=len(installation_steps)
            )
            
            for func, desc in installation_steps:
                progress.update(main_task, description=f"[cyan]{desc}")
                func()
                progress.advance(main_task)
                sleep(0.2)

        finalize_installation(ip)

    except Exception as e:
        console.print(Panel.fit(
            f"[bold red] Installation Failed [/]\n{str(e)}",
            style=Style(color="red", bold=True)),
            justify="center"
        )
        sys.exit(1)

if __name__ == "__main__":
    main()
