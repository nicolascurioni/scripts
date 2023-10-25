### Description

This script is intended to perform the Docker installation in different Linux distributions. You can specify the distro that you're running on the server, or let the script automatically identify it. 

So far, these are the supported distributions: 

* Ubuntu
* Debian
* Kali
* Centos 
* Rocky
* Almalinux

### Pre-requisites
1- Place the file in the server

2- Open a terminal and navigate to the directory where the script was placed.

3- Give the script execution permissions. You can do so with the following command 

```
chmod +x docker-install.sh

```

### Usage

`/docker-install.sh [-s <os>] [-h] [-y]`

Options:

  `-s <os>`        Specify the operating system. Supported values: ubuntu, debian, kali, centos, rocky, almalinux.
  
  `-h`             Show this help message.
  
  `-y`             Avoid asking for confirmation when installing 
  


