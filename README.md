# Security Notes
Table of Contents
=================
  * [Table of Contents](#table-of-contents)
  * [<strong>Recon</strong>](#recon)
    * [nmap](#nmap)
    * [Port 139/445 - SMB](#port-139445---smb)    
    
# **Recon**

## nmap
``` 
# Escaneo nmap
nmap -sV -sC 10.10.10.10

# Escaneo nmap
nmap -sV -sC 10.10.10.10 -Pn

# Escaneo nmap UDP
nmap -sV -sC -sU 10.10.10.10
```

## Port 139/445 - SMB
```

smbclient -L 10.10.10.10

smbclient.py -u user -p password -i 10.10.10.10

smbmap -u user -p password -H 10.10.10.10


```
