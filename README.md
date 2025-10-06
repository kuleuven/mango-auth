# Mango Auth

Mango Auth is a small python module to authenticate using interactive pam authentication against an iRODS installation, opening web browser links as needed.

## Usage

```shell
$ pip install mango_auth
$ mango_auth <irods_user_name> <irods_zone_name>
2025-10-06 16:24:44,513 - irods.auth.pam_interactive - INFO - Server prompt: Please authenticate at https://mango-auth.icts.kuleuven.be/oauth/device/auth?user_code=XXXXXXXXXX
Opening browser for authentication: https://mango-auth.icts.kuleuven.be/oauth/device/auth?user_code=XXXXXXXXXX
2025-10-06 16:25:04,745 - irods.auth.pam_interactive - INFO - Server prompt: You are authenticated using a device code.
```

## Development

```shell
$ python -m venv venv
$ . venv/bin/activate
$ pip install -r requirements.txt 
$ pip install --editable src
```
