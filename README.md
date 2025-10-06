# Mango Auth

Mango Auth is a small python module to authenticate using interactive pam authentication against an iRODS installation, opening web browser links as needed.

## Installation

```bash
python -m venv venv
. venv/bin/activate
pip install -r requirements.txt 
pip install --editable src
```

## Usage

```bash
mango-auth <irods_user_name> <irods_zone_name>
```
