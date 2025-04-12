# WAF Interface Installer
Welcome user! you can easily now install your waf interface over modsecurity in the robost and fast as possible!

## Prerequisites
- **Operating System**: Debian-based (e.g., Debian 11/12, Ubuntu 20.04/22.04).
- **Root Access**: You need to be a root user(for example on debain use the su root on the debain) for running it.
- **Python Needs!**: The script requires `python3` to start installing process.
- **Internet Access**: Needed to download dependencies and components.

## Installing
- **First clone lasted version**: Use this command to download the lasted installer immedently( or just clone it without using release):
```
git clone https://github.com/Waf-Interface/Installer

cd Installer
```
- **Start the installer**: Install it using this command( make sure you are a root user):
```
python3 installer.py
```
- **Important!**: After successfull installation , using waf-interface command to add a new user( ADMIN! add user **Admin**) like this:
```
waf-interface --user-add

=== Add New User ===
Username*: test
Password*: ****
Confirm Password*: ****
First Name: test
Last Name: test
Email: test
Role (admin/user)*: admin
User added successfully!
```
**For more information about this waf-interface cli contrller( https://github.com/Waf-Interface/Cli-Controller ).**

## What does this installaer do?
- The installer will:
- Clean previous installations
- Install system dependencies
- Build Nginx with ModSecurity
- Configure OWASP CRS rules
- Set up Python backend (FastAPI) and frontend (Apache)
- Create SSL certificates
- Configure systemd services

## What happaning after?
**Nginx (Port 80/443): Reverse proxy with ModSecurity**

**Apache (Port 8080): Serves frontend assets**

**Python Backend (Port 8081): FastAPI service for WAF management**

**Security: OWASP CRS v3.3.4 with custom rules**


## Installation script review
- **Using lasted build WASM from Waf2Flutter**
- **Using methods for roubost installing without needing proumt other things!**
- **Easy even for people who doesnt know terminal even through they have server!** 

Use it with cution this app is currently in beta version Absoluty NO WARANTY.
This version of installer designed for only working without any security measures and running via self certificate.
We are naming waf-gh<[f] frontend ,[b] backend, [c] controller, [m] manager> for fun, but its actually made us see this important subject.


**Creator: mortza mansori**
***Team: Dadeh Pardazan Oxin***
