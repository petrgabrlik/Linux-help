# Samba

## Installation
Update package info and upgrade
```
apt-get update
apt-get upgrade
```

Download an install samba
```
apt-get install samba samba-common-bin
```

Set samba password for user
```
smbpasswd -a user
```

Restart samba to save changes
```
/etc/init.d/samba restart
```

## Usage
### Mac OS
Connect using Finder:
1. Start Finder
2. cmd-k or Open->Connect to server
3. write (and save) address, eg `smb://192.168.0.1/user`

### Windows

## Configuration
