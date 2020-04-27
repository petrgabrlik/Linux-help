Ubuntu Serever 18.04 installation on RPi 4 using Mac OS
==========

Download image
-------
- download desired version from ubuntu.com
- verify download, eg. `echo "f270d4a11fcef7f85ea77bc0642d1c6db2666ae734e9dcc4cb875a31c9f0dc57 *ubuntu-18.04.4-preinstalled-server-arm64+raspi3.img.xz" | shasum -a 256 --check`, respond should be `OK`

Preparing SD card (Mac OS)
-------
- insert and mount SD card into Mac 
- find address of the SD card in the system using `diskutil list`, eg. `/dev/disk2`
- format the card: `sudo diskutil eraseDisk FAT32 SDCARD MBRFormat <drive address>`, `SDCARD` is new name
- verify formatting `diskutil list`
- unmount: `diskutil unmountDisk <drive address>`
- copy the image to the SD card: `sudo sh -c 'gunzip -c ~/Downloads/<image file> | sudo dd of=<drive address> bs=32m'`, it may take a few minutes
- unmount the card

First boot and login
------
- insert the SD card into the RPi, power it up 
- connect via ssh (ssh server is enabled by default), use `ssh ubuntu@<ip addr>`, default password `ubuntu`
- password must be changed after the first login

Create new user (optional)
------
- change default umask (022 in Debian) for new user's home direcotry to 077 (to increase privacy): set line `UMASK 077` in `/etc/login.defs`. Another option is to change the home directory permissions individually after creation using `chmod 700 /home/<user>`
- new user's home direcotry will be based on `/etc/skel/` directory
- read groups of the default user ubuntu from `/etc/group` or `id ubuntu`, eg.: `std_groups=$(cat /etc/group | grep ubuntu$ | cut -f1 -d: | tr "\n" "," | sed 's/,$//')`
- (read `useradd` defaults via `useradd -D` or `/etc/defaults/useradd` ??)
- add a new user: `sudo useradd -m -G <groups> -s /bin/bash -c "comment" <user>`, `-m` stands for "create home directory", groups may be separated by comma 
- set password: `passwd <user>`

Update system
-----
- `apt-get update` `apt-get upgrade`

Set passwordless ssh connection
-------
- on the client: use existing key, or generate new one: TODO
- copy the public key from client to the host using `ssh-copy-id -i ~/.ssh/id_rsa.pub <user>@<host>` or manually into `/home/<user>/.ssh/authorized_keys` file

Other system settings
-------
- change default hostname (ubuntu) to another one using `hostnamectl set-hostname <new hostname>` on newer systems with 'systemd'; read current hostname using `hostnamectl` or `hostname` commands, or from `/etc/hostname`


notes
-----
- remove user `userdel <user>` does not delete home dir and mail spool, `userdel -r <user>` deletes all
- ssh known hosts: when connecting to a host for the first time, verify host's public key hash before adding host into `~/.ssh/known_hosts` (the hash is displayed automatically when trying to connect); use `ssh-keygen -l -E sha256 -f <host's public key>` to compute the hash. In the case of man-in-the-middle attack, the hash of the "host" changes, and user is promted to save the host into known_hosts again - don't do that automatically!
- ssh root login via password is disabled by default: in `/etc/ssh/sshd_config` is default `PermitRootLogin prohibit-password`. To enable the password login (for key upload using `ssh-copy-id`, for example), change `PermitRootLogin yes` and restart ssh service `service ssh restart`. After key uploading, disable password login again.
