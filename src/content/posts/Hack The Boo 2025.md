---
title: Hack The Boo 2025
published: 2025-10-28
tags: [Forensics]
category: Writeup CTF Challenge
draft: false
---

# Hack The Boo 2025 - Competition

**Note:** I'm not a native English speaker so my English is not good, please feedback to me if my wu have any mistake.

## When The Wire Whispered
> Brynn’s night-threads flared as connections vanished and reappeared in reverse, each route bending back like a reflection misremembered. The capture showed silent gaps between fevered bursts—packets echoing out of sequence, jittering like whispers behind glass. Eira and Cordelia now sift the capture, tracing the pattern’s cadence to learn whether it’s mere corruption… or the Hollow King learning to speak through the wire. Note: Make sure you are using Wireshark v4.6.0+ Note2: Use PyRDP *git* version
> Difficult: Medium

There are the pcap file, PASSWORDS.TXT, USERS.TXT and tls key log file.

### What is the username affected by the spray?

Open the pcap file to analysis(Use tls key to decrypt tls). Overview of this, there are a lot of packet RDP(Remote Desktop Protocol), view the Graph:

![image](https://hackmd.io/_uploads/Skorkm6Alx.png)

After this:
![upload_c59556abfe8e731f258a5a37227d3941](https://hackmd.io/_uploads/BkGglmT0xe.png)

I things maybe attacker was successed bruteforce to remote to victim desktop and try to mark data for victim, check it.
![image](https://hackmd.io/_uploads/BJHOxQTAeg.png)
**negResult: accept-completed**

**Answer: stoneheart_keeper52**

### What is the password for that username

In the image pcap of Q1, we can see it authenticate by CredSSP/NTLM.
How CredSSP/NTLM works:

![image](https://hackmd.io/_uploads/HJLmEQaReg.png)
![image](https://hackmd.io/_uploads/ryH7BQTCxx.png)
It's NTLMv2.
We can crack the password by hashcat mode 5600(NTLMv2) with wordlist PASSWORD.TXT that author give. 
This is format of mode 5600:
``USERNAME::DOMAIN:SERVER_CHALLENGE:NTPROOFSTR:BLOB``

That ``NTPROOFSTR`` is first 16 bytes and ``BLOB`` is the rest of ``NTLMv2 Response``.

This is the hash:
```
stoneheart_keeper52::DESKTOP-6NMJS1R:378e0e0b4a481c08:460120880eecc460649883618863cea1:010100000000000060a10ae3f541dc01e803174c6a90ce7e0000000002001e004400450053004b0054004f0050002d0036004e004d004a0053003100520001001e004400450053004b0054004f0050002d0036004e004d004a0053003100520004001e004400450053004b0054004f0050002d0036004e004d004a0053003100520003001e004400450053004b0054004f0050002d0036004e004d004a0053003100520007000800379915e3f541dc0109004e007400650072006d007300720076002f004400450053004b0054004f0050002d0036004e004d004a0053003100520040004400450053004b0054004f0050002d0036004e004d004a005300310052000000000000000000
```

![image](https://hackmd.io/_uploads/HyeorX6Ceg.png)

**Answer: Mlamp!J1**

### What is the website the victim is currently browsing. (TLD only: google.com)

Now, to know what website the victim is currently browsing, we only view the replay of desktop victim when attacker connect to it. And I will use **PyRDP** for it.

Link to download: https://github.com/GoSecure/pyrdp

![image](https://hackmd.io/_uploads/B1eVvQTAxg.png)

We need a .pyrdp file to use this command.

![image](https://hackmd.io/_uploads/ryuUvX6Cxg.png)

Nice, there are instructions for use in that github.

Now, we extract PDUs Layer 7 and filter 2 IP `192.168.56.1` and `192.168.56.102` to a pcap file.
After that, use pyrdp-convert to convert .pcap to .pyrdp and use pyrdp-player to watch the replay desktop.

![image](https://hackmd.io/_uploads/SkfHOQ6Cle.png)

**Answer: thedfirreport.com**

### What is the username:password combination for website `http://barrowick.htb`

Continue to watch the replay, and we can see attacker open cmd and paste a ps1 code to copy the imformation about browser of victim to clipboard, and **pyRDP** is too strong, that can record the data when copy to clipboard. Easily, I just view that data and have the answer.

![image](https://hackmd.io/_uploads/BJJHtmaRxe.png)
![image](https://hackmd.io/_uploads/ryurtXp0gx.png)

```
CLIPBOARD DATA: 

id                     : 2
hostname               : http://brackenrow.htb
formSubmitURL          : 
usernameField          : 
passwordField          : 
guid                   : {8fa8b071-2544-40da-9801-3b67e037a5aa}
encType                : 1
timeCreated            : 1760985367574
timeLastUsed           : 1760985367574
timePasswordChanged    : 1760985367574
timesUsed              : 1
syncCounter            : 1
everSynced             : False
encryptedUnknownFields : MEMEEPgAAAAAAAAAAAAAAAAAAAEwHQYJYIZIAWUDBAEqBBDU35ezznMbDQ4SEQKSGEJ0BBDJgwBqBZrRfOkwppqr4uvX
username               : tallow_keeper
password               : Wax&Whisper_1313

id                     : 3
hostname               : http://hollowmere.htb
formSubmitURL          : 
usernameField          : 
passwordField          : 
guid                   : {f79ade19-f19a-44c2-b4ef-2df810ee66fc}
encType                : 1
timeCreated            : 1760985367584
timeLastUsed           : 1760985367584
timePasswordChanged    : 1760985367584
timesUsed              : 1
syncCounter            : 1
everSynced             : False
encryptedUnknownFields : MEMEEPgAAAAAAAAAAAAAAAAAAAEwHQYJYIZIAWUDBAEqBBBgwy1nFzgBD22mcvG6yPsIBBAR/Xf9kN0EX5qrJynf376U
username               : bone_riddle
password               : Cipher.of.Marrows!

id                     : 4
hostname               : http://oakhurstwatch.htb
formSubmitURL          : 
usernameField          : 
passwordField          : 
guid                   : {ce21b0df-d1bf-473b-ae3c-121655dce4f6}
encType                : 1
timeCreated            : 1760985367592
timeLastUsed           : 1760985367592
timePasswordChanged    : 1760985367592
timesUsed              : 1
syncCounter            : 1
everSynced             : False
encryptedUnknownFields : MEMEEPgAAAAAAAAAAAAAAAAAAAEwHQYJYIZIAWUDBAEqBBAMTSKG67hjRBPvJo6dI64+BBDCI5HcBudCU9rSKU5bY6q2
username               : night_threader
password               : ThreadSight_03$Moon

id                     : 5
hostname               : http://barrowick.htb
formSubmitURL          : 
usernameField          : 
passwordField          : 
guid                   : {23a64d8d-6327-48fd-9042-b4ef6b0acf5d}
encType                : 1
timeCreated            : 1760985367604
timeLastUsed           : 1760985367604
timePasswordChanged    : 1760985367604
timesUsed              : 1
syncCounter            : 1
everSynced             : False
encryptedUnknownFields : MEMEEPgAAAAAAAAAAAAAAAAAAAEwHQYJYIZIAWUDBAEqBBBwdJwssMn5gPitwx8QISEEBBBu/b1b3BL4X0aDv5BjRPn5
username               : candle_eyed
password               : AshWitness_99@Tomb

id                     : 6
hostname               : http://ashforge.htb
formSubmitURL          : 
usernameField          : 
passwordField          : 
guid                   : {7a21c145-a54a-4741-a01f-e1ea0564e165}
encType                : 1
timeCreated            : 1760985367612
timeLastUsed           : 1760985367612
timePasswordChanged    : 1760985367612
timesUsed              : 1
syncCounter            : 1
everSynced             : False
encryptedUnknownFields : MEMEEPgAAAAAAAAAAAAAAAAAAAEwHQYJYIZIAWUDBAEqBBBg7Q9rquK52OAgr3bwdj2WBBCyFMzYg+RcukfrQqPIGLy+
username               : ash_apprentice
password               : IronLock_Breaker42

id                     : 7
hostname               : http://lornmerelocks.htb
formSubmitURL          : 
usernameField          : 
passwordField          : 
guid                   : {f681bc16-b725-464f-b437-715ce03a2a07}
encType                : 1
timeCreated            : 1760985367618
timeLastUsed           : 1760985367618
timePasswordChanged    : 1760985367618
timesUsed              : 1
syncCounter            : 1
everSynced             : False
encryptedUnknownFields : MEMEEPgAAAAAAAAAAAAAAAAAAAEwHQYJYIZIAWUDBAEqBBBUNikG1gk1NXad5luPHCtoBBA1TiOabIpjb/rxTQUj+kat
username               : knot_weaver
password               : RuleBound_7xThorn

id                     : 8
hostname               : http://emberreach.htb
formSubmitURL          : 
usernameField          : 
passwordField          : 
guid                   : {8b9d44a1-93bb-4ac5-bec5-9f5a67b84444}
encType                : 1
timeCreated            : 1760985367631
timeLastUsed           : 1760985367631
timePasswordChanged    : 1760985367631
timesUsed              : 1
syncCounter            : 1
everSynced             : False
encryptedUnknownFields : MEMEEPgAAAAAAAAAAAAAAAAAAAEwHQYJYIZIAWUDBAEqBBDkXuSMkm25zhXrt2ijIMaqBBD2nnQqm7vRhijrm6C5foba
username               : memory_tinker
password               : Reverse.Time_404!
```

**Answer: candle_eyed:AshWitness_99@Tomb**

## Watchtower Of Mists
> The tower’s lens, once clear for stargazing, was now veiled in thick mist. Merrin, a determined forensic investigator, climbed the spiraling stairs of Egrath’s Hollow. She found her notes strangely rearranged, marked with unknown signs. The telescope had been deliberately turned downward, focused on the burial grounds. The tower had been occupied after a targeted attack. Not a speck of dust lay on the glass, something unseen had been watching. What it witnessed changed everything. Can you help Merrin piece together what happened in the Watchtower of Mists?
> Difficult: Easy

There is a pcap file for this challenge.
Preview of this, I think user was use the API of LangFlow to do somethings.

### What is the LangFlow version in use? (e.g. 1.5.7)

![image](https://hackmd.io/_uploads/BygYc7aRex.png)

**Answer: 1.2.0**

### What is the CVE assigned to this LangFlow vulnerability? (e.g. CVE-2025-12345)

![image](https://hackmd.io/_uploads/By0fimTCgg.png)

**Answer: CVE-2025-3248**

### What is the name of the API endpoint exploited by the attacker to execute commands on the system? (e.g. /api/v1/health)

![image](https://hackmd.io/_uploads/rymN27pAel.png)

We can see they are execute the python code in this endpoint.

**/api/v1/validate/code**

### What is the IP address of the attacker? (format: x.x.x.x)

![image](https://hackmd.io/_uploads/B1fm6maCeg.png)
We can see the ip which send the payload to execute.
**Answer: 188.114.96.12**

### The attacker used a persistence technique, what is the port used by the reverse shell? (e.g. 4444)

Decode the last payload and have this:
![image](https://hackmd.io/_uploads/SJLoxEp0le.png)
Continue:
![image](https://hackmd.io/_uploads/HkV2gETRlx.png)

**Answer: 7852**

### What is the system machine hostname? (e.g. server01)

![image](https://hackmd.io/_uploads/r1gRlVpRgg.png)

Decode the payload first:
![image](https://hackmd.io/_uploads/rylMWNTAxe.png)

It print the environment variable and we can see the system machine hostname in the response.

```
{"imports":{"errors":[]},"function":{"errors":["b'TOKENIZERS_PARALLELISM=false\\nHOSTNAME=aisrv01\\nPYTHON_PIP_VERSION=24.0\\nHOME=/app/data\\nLANGFLOW_DATABASE_URL=postgresql://langflow:LnGFlWPassword2025@postgres:5432/langflow\\nLANGFLOW_HOST=0.0.0.0\\nGPG_KEY=7169605F62C751356D054A26A821E680E5FA6305\\nOPENAI_API_KEY=dummy\\nASTRA_ASSISTANTS_QUIET=true\\nLANGFLOW_PORT=7860\\nLANGFLOW_CONFIG_DIR=app/langflow\\nPYTHON_GET_PIP_URL=https://github.com/pypa/get-pip/raw/dbf0c85f76fb6e1ab42aa672ffca6f0a675d9ee4/public/get-pip.py\\nSERVER_SOFTWARE=gunicorn/23.0.0\\nGRPC_VERBOSITY=ERROR\\nPATH=/app/.venv/bin:/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\\nTIKTOKEN_CACHE_DIR=/app/.venv/lib/python3.12/site-packages/litellm/litellm_core_utils/tokenizers\\nLANG=C.UTF-8\\nPYTHON_VERSION=3.12.3\\nPWD=/app\\nPYTHON_GET_PIP_SHA256=dfe9fd5c28dc98b5ac17979a953ea550cec37ae1b47a5116007395bfacff2ab9\\nUSER_AGENT=langflow\\n'"]}}
```

**Answer: aisrv01**

### What is the Postgres password used by LangFlow? (e.g. Password123)

In that response on Q6, we can see the answer for this question.

**Answer: LnGFlWPassword2025**