import logging
import sys
import webbrowser
import re
import os
import os.path
import platform
import json
import irods
from irods.session import iRODSSession
from irods.password_obfuscation import encode

class AuthenticationHandler(logging.Handler):
    """Custom logging handler that opens browser for authentication URLs."""
    
    def __init__(self, level=logging.INFO):
        super().__init__(level)
        # Pattern to match "Server prompt: Please authenticate at url"
        self.auth_pattern = re.compile(r'Server prompt: Please authenticate at (https?://[^\s]+)', re.IGNORECASE)
    
    def emit(self, record):
        # Format and print the log message
        msg = self.format(record)
        print(msg)
        
        # Check if this is an authentication message
        if record.levelno == logging.INFO:
            match = self.auth_pattern.search(record.getMessage())
            if match:
                url = match.group(1)
                print(f"Opening browser for authentication: {url}")
                try:
                    webbrowser.open(url)
                except Exception as e:
                    print(f"Failed to open browser: {e}")

config_template = {
    "irods_host": "{irods_host}",
    "irods_port": 1247,
    "irods_zone_name": "{irods_zone_name}",
    "irods_authentication_scheme": "pam_interactive",
    "irods_encryption_algorithm": "AES-256-CBC",
    "irods_encryption_salt_size": 8,
    "irods_encryption_key_size": 32,
    "irods_encryption_num_hash_rounds": 8,
    "irods_user_name": "{irods_user_name}",
    "irods_ssl_ca_certificate_file": "",
    "irods_ssl_verify_server": "cert",
    "irods_client_server_negotiation": "request_server_negotiation",
    "irods_client_server_policy": "CS_NEG_REQUIRE",
    "irods_default_resource": "default",
    "irods_cwd": "/{irods_zone_name}/home",
}

def check_version():
    if irods.__version__.startswith(("0.", "1.", "2.", "3.1.")):
        raise Exception("You are using an outdated version %s of the python irods client. Please update to 3.2.0 to use this tool." % irods.__version__)

def register_webbrowser_handler():
    root = logging.getLogger()
    root.setLevel(logging.INFO)

    handler = AuthenticationHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    handler.setLevel(logging.INFO)

    root.addHandler(handler)

def put(file, contents):
    os.makedirs(os.path.dirname(file), exist_ok=True)
    with open(file, "w") as f:
        f.write(contents)

def get_config(irods_user_name, irods_zone_name, irods_host = '', **kwargs):
    if irods_host == '':
        if irods_zone_name.startswith('vsc'):
            irods_host = f"{irods_zone_name}.irods.hpc.kuleuven.be"
        else:
            irods_host = f"{irods_zone_name}.irods.icts.kuleuven.be"

    def format(val):
        if isinstance(val, str):
            return val.format(irods_user_name=irods_user_name, irods_zone_name=irods_zone_name, irods_host=irods_host)
        else:
            return val

    config = dict(map(lambda kv: (kv[0], format(kv[1])), config_template.items()))

    if platform.system() == 'Windows':
        config["irods_authentication_uid"] = '1000'

    config.update(kwargs)

    return config

def iinit(irods_user_name, irods_zone_name, irods_host = '', **kwargs):
    check_version()
    register_webbrowser_handler()

    # Write config
    config = get_config(irods_user_name, irods_zone_name, irods_host, **kwargs)
    env_file = os.getenv('IRODS_ENVIRONMENT_FILE', os.path.expanduser('~/.irods/irods_environment.json'))
    put(env_file, json.dumps(config))

    # Remove previous .irodsA file
    if os.path.exists(iRODSSession.get_irods_password_file()):
        os.remove(iRODSSession.get_irods_password_file())

    # Get a session and enforce authentication
    with iRODSSession(irods_env_file=env_file) as session:
        conn = session.pool.get_connection()
        conn.release()

def iinit_cli():
    iinit(*sys.argv[1:])
