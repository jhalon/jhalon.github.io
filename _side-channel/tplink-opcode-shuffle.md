---
layout: single
title: "Unshuffling TP-Link: Building a Custom Luadec for Shuffled Opcodes"
date: 2026-01-20
header:
  overlay_image: side-channel.jpg
---

Over the holiday weekend I was at my parents house and noticed they got a new WiFi router, a [TP-Link Archer AX1800](https://www.tp-link.com/us/home-networking/wifi-router/archer-ax1800/). Honestly, it seemed like a pretty good choice for their needs: decent speeds, good range, and the price was right. 

But being bored and having my laptop with me, I figured why not see if I could pull apart the firmware and maybe find a bug or two? What's the worst that could happen?

Well... what I thought was going to be a quick evening of poking through some code turned into a multi-day deep dive into firmware encryption, Lua bytecode shenanigans, and build system archaeology to get a single tool to work.

## Dumping the Firmware

To start, I needed to get my hands on the actual firmware. TP-Link makes this pretty easy by hosting firmware downloads on their support page. A quick visit to the [Archer AX1800 Support Page](https://www.tp-link.com/us/support/download/archer-ax1800/#Firmware) and we're in business.

```shell
$ wget https://static.tp-link.com/upload/firmware/2025/202509/20250905/Archer%20AX1800(USW)_V5.6_250814.zip
$ unzip Archer\ AX1800\(USW\)_V5.6_250814.zip 
Archive:  Archer AX1800(USW)_V5.6_250814.zip
 extracting: ax1800v5-up-all-ver1-1-2-P1[20250814-rel14122]-2048_sign_2025-08-14_17.27.42.bin  
  inflating: GPL License Terms.pdf   
  inflating: How to upgrade TP-Link Wireless Router.pdf  
```

With the firmware binary in hand, we can utilize `binwalk` to see what we're dealing with.

```shell
$ binwalk ax1800v5-up-all-ver1-1-2-P1\[20250814-rel14122\]-2048_sign_2025-08-14_17.27.42.bin 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
5648403       0x563013        JBOOT STAG header, image id: 4, timestamp 0x11ECC785, image size: 3311391534 bytes, image JBOOT checksum: 0x66EE, header JBOOT checksum: 0xEEDE
10766856      0xA44A08        JBOOT STAG header, image id: 9, timestamp 0xAE881B7B, image size: 3519414550 bytes, image JBOOT checksum: 0x1CC0, header JBOOT checksum: 0x2BB6
11569564      0xB0899C        lrzip compressed data
16523881      0xFC2269        JBOOT STAG header, image id: 8, timestamp 0x54F62A8C, image size: 2061780559 bytes, image JBOOT checksum: 0x1396, header JBOOT checksum: 0xE99E
```

Upon inspection of the output the `lrzip` data is interesting, but those JBOOT headers with weird timestamps and massive image sizes usually isn't a great sign - this might mean that the firmware is encrypted. Still, we can try extracting the firmware to see what happens.

```shell
$ binwalk -e ax1800v5-up-all-ver1-1-2-P1\[20250814-rel14122\]-2048_sign_2025-08-14_17.27.42.bin 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------

WARNING: One or more files failed to extract: either no utility was found or it's unimplemented
```

Yeah, that's what I thought, the firmware is encrypted. Not super surprising for a modern router, but it means we can't just `binwalk -e` our way to victory. Time to do some research.

## Finding the Decryption Key

After some digging around (and a few cups of coffee), I came across a blog post by [evilsocket](https://x.com/evilsocket) titled "[TP-Link Tapo C200: Hardcoded Keys, Buffer Overflows and Privacy in the Era of AI Assisted Reverse Engineering](https://www.evilsocket.net/2025/12/18/TP-Link-Tapo-C200-Hardcoded-Keys-Buffer-Overflows-and-Privacy-in-the-Era-of-AI-Assisted-Reverse-Engineering/)".

Upon reading his blog post the key takeaway I got was that every firmware image for every TP-Link device seems to be encrypted the same exact way. He also provided a link to the [tp-link-decrypt](https://github.com/robbins/tp-link-decrypt) tool, which extracts RSA keys from TP-Link's own GPL code releases and uses them to decrypt firmware images.

At first I was skeptical. The blog post and decryption tools were targeting the C200 and C210 cameras, a completely different product line from routers. Would TP-Link really use the same encryption scheme across cameras and routers? That seems... insane, even by IoT security standards.

Regardless of that, when you're bored at your parents house you might as well try it. What's the worst that could happen if it doesn't work and I wasted five minutes?

```shell
$ ./tp-link-decrypt/bin/tp-link-decrypt ax1800v5-up-all-ver1-1-2-P1\[20250814-rel14122\]-2048_sign_2025-08-14_17.27.42.bin 

TP-link firmware decrypt

Watchful_IP & robbins 03-10-25 v0.0.4
watchfulip.github.io

fw-type: found
RSA-2048

key/iv:
KEY=c096c4172037358bd5c1ae09611d4c6d
IV=bb828a2ea51d93ee497c4f2567989f17

Firmware verification successful

Decrypted firmware written to ax1800v5-up-all-ver1-1-2-P1[20250814-rel14122]-2048_sign_2025-08-14_17.27.42.bin.dec
```

Hold on... this can't be real, right?

```shell
$ binwalk -e ax1800v5-up-all-ver1-1-2-P1\[20250814-rel14122\]-2048_sign_2025-08-14_17.27.42.bin.dec 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
4950          0x1356          UBI erase count header, version: 1, EC: 0x0, VID header offset: 0x800, data offset: 0x1000
```

It's real... that's pretty insane! TP-Link really does use the same encryption keys across their entire product line - cameras, routers, switches, probably their coffee makers too if they made those.

With that we now have access to the `squashfs-root` filesystem for the firmware and can dig into code and look for vulnerabilities!

```shell
$ ls -la extracted/squashfs-root    
total 68
drwxrwxrwx 17 kali kali 4096 Jan 11 20:26 .
drwxrwxr-x  4 kali kali 4096 Jan 12 00:44 ..
drwxrwxrwx  2 kali kali 4096 Aug 22  2024 bin
drwxrwxrwx  2 kali kali 4096 Aug 22  2024 dev
drwxrwxrwx 21 kali kali 4096 Jan 11 20:26 etc
drwxrwxrwx  6 kali kali 4096 Aug 22  2024 etc_ro
drwxrwxrwx 40 kali kali 4096 Jul 30  2024 lib
drwxrwxrwx  2 kali kali 4096 Aug 22  2024 mnt
drwxrwxrwx  2 kali kali 4096 Aug 22  2024 overlay
drwxrwxrwx  2 kali kali 4096 Aug 22  2024 proc
drwxrwxrwx  2 kali kali 4096 Aug 22  2024 rom
drwxrwxrwx  2 kali kali 4096 Aug 22  2024 root
drwxrwxrwx  2 kali kali 4096 Aug 22  2024 sbin
drwxrwxrwx  2 kali kali 4096 Aug 22  2024 sys
drwxrwxrwx  2 kali kali 4096 Aug 22  2024 tmp
drwxrwxrwx  7 kali kali 4096 Jul 30  2024 usr
lrwxrwxrwx  1 kali kali    9 Jan 11 20:26 var -> /dev/null
drwxrwxrwx  5 kali kali 4096 Aug 22  2024 www

```

## Exploring the Web Interface

With the firmware extracted, I started poking around to understand how the router's web interface works. Looking at the filesystem structure it was clear that a lot of the client-side logic is handled via JavaScript in the `www/webpages` directory.

For example, the login flow is handled by `www/webpages/modules/login/localLogin/controllers.js`, which uses AJAX to communicate with the backend:

```js
(function($) {
    $.su.moduleManager.define("localLogin", {
        services: ["ajax"],
        models: ["localLogin", "localLoginControl", "vercodeModel", "resetPwdModel"],
        views: ["localLoginView"],
        deps: ["login", "main"],
        listeners: {
            ev_on_launch: function(event, params, models, views, control, router, ajax) {
                views.localLoginView.noInternetTips.hide();
                ajax.request({
                    proxy: "keyProxy",
                    success: function(response) {
                        if (response && response.password) {
                            control.encryptKey = response.password;
                        }
                    }
                });
            }
        },
// ... snip ...
```

One thing that stood out to me during code review is they use something called a `moduleManager` to handle and load the different models for the specific controller. This suggests there is probably some more backend functionality that TP-Link uses for their web apps that we are unaware of.

If we look into the `doLogin` function for the `localLogin` controller, we'll find some interesting crypto related code: 

```js
methods: {
    enableConfirm: false,
    receiveCodeTimeCount: 60,
    countDownTimer: null,
    encryptKey: null,
    vercode: "",
    doLogin: function() {
        var password, encryptedPassword;
        if (!this.encryptKey) return;
        if (models.localLoginControl.validate()) {
            password = models.localLoginControl.password.getValue();
            encryptedPassword = models.localLoginControl.password.doEncrypt(this.encryptKey);
            models.localLogin.password.setValue(encryptedPassword);
            views.localLoginView.localLoginBtn.loading(true);
            ajax.request({
                proxy: "authProxy",
                success: function(response) {
                    $.su.encryptor.setRSAKey(response.key[0], response.key[1]);
                    $.su.encryptor.setSeq(response.seq);
                    $.su.encryptor.genAESKey();
                    $.su.encryptor.setHash("admin", password);
                    $.encrypt.encryptManager.recordEncryptor();
                    models.localLogin.login({
                        preventFailEvent: true,
                        success: this.loginSuccessDealer,
                        fail: this.loginFailDealer,
                        error: this.loginErrorDealer
                    });
                },
                error: this.loginErrorDealer
            });
        }
    }
```

The `vercode` string and the password encryption logic caught my attention. I figured if there's a vulnerability here, it's probably in how the backend validates credentials or there is some weak crypto/password generation that can be exploited. Time to look at the server-side code.

A quick grep for the term `vercode` revealed it's referenced in several binary files:

```shell
grep: lib/modules/iplatform/xt_pctl.ko: binary file matches
grep: usr/lib/lua/luci/model/passwd_recovery.lua: binary file matches
grep: usr/lib/lua/luci/controller/admin/administration.lua: binary file matches
grep: usr/lib/lua/luci/controller/login.lua: binary file matches
grep: usr/lib/lua/luci/service.lua: binary file matches
```

Looking at these files, we can conclude that the backend is written in Lua and lives in the `usr/lib/lua/luci/` directory which is pretty common for OpenWRT-based routers. The problem? These aren't plain text Lua files, they're compiled Lua bytecode.

## The Luadec Problem 

I've never reversed Lua bytecode before, but there's a well-known tool for this called [`luadec`](https://github.com/viruscamp/luadec). So I downloaded the tool, compiled it, and attempted to execute it against the compiled Lua code.

```shell
$ luadec extracted/squashfs-root/usr/lib/lua/luci/controller/login.lua 
luadec: extracted/squashfs-root/usr/lib/lua/luci/controller/login.lua: bad header in precompiled chunk
```

Interesting - usually a bad header indicates an incompatibility between the Lua bytecode file and the Lua decompiler. After digging through GitHub issues and StackOverflow posts, the consensus seems to be that we're using the wrong Lua version.

I found a couple of really helpful resources while researching this:
* "[Lua Bytecode VM Notes](https://gist.github.com/seanjensengrey/e198380afc64f0eb17a47512b48f040)"
* "[Making a Lua Bytecode Parser in Python](https://openpunk.com/pages/lua-bytecode-parser/)"

Let's take a look at the bytecode header to understand what we're dealing with:

```shell
$ hexdump -C extracted/squashfs-root/usr/lib/lua/luci/controller/login.lua
00000000  1b 4c 75 61 51 00 01 04  04 04 08 04 00 00 00 00  |.LuaQ...........|
00000010  00 00 00 00 00 00 00 00  00 00 02 23 a5 01 00 00  |...........#....|
00000020  01 00 00 00 48 40 00 00  81 80 00 00 80 c0 40 01  |....H@........@.|
00000030  22 40 80 01 01 00 01 00  48 40 01 00 22 80 00 01  |"@......H@.."...|
00000040  41 00 01 00 88 80 01 00  62 80 00 01 81 00 01 00  |A.......b.......|
00000050  c8 c0 01 00 a2 80 00 01  c1 00 01 00 08 01 02 00  |................|
```

Looking into the header via `hexdump` we can see `LuaQ` which stands for LUA v5.1, and that's the exact same version we used when building `luadec`. Let's take a closer look at the first 12 bytes of the header which contains metadata about how the bytecode was compiled.

| Offset  | Standard Lua 5.1 | TP-Link Value | Description                                               |
| ------- | ---------------- | ------------- | --------------------------------------------------------- |
| 0x00    | `1b`             | `1b`          | **ESC signature** - Marks the start of Lua bytecode       |
| 0x01-03 | `4c 75 61`       | `4c 75 61`    | **"Lua"** - Magic signature string                        |
| 0x04    | `51`             | `51`          | **Version** - 0x51 = Lua 5.1                              |
| 0x05    | `00`             | `00`          | **Format version** - Official bytecode format             |
| 0x06    | `01`             | `01`          | **Endianness** - 0x01 = little-endian                     |
| 0x07    | `04`             | `04`          | **sizeof(int)** - 4 bytes (32-bit integers)               |
| 0x08    | `04`             | `04`          | **sizeof(size_t)** - 4 bytes (32-bit architecture)        |
| 0x09    | `04`             | `04`          | **sizeof(Instruction)** - 4 bytes per opcode              |
| 0x0A    | `08`             | `08`          | **sizeof(lua_Number)** - 8 bytes (double precision float) |
| 0x0B    | **`00`**         | **`04`**      | **Number type flag**                                      |

Everything looks standard until we hit byte `0x0B`. Byte `0x0B` should be `00` in standard Lua 5.1, where `00` is a floating-point number representation and `01` is a integral number type. But TP-Link's firmware has **`04`** instead. This single byte difference confirms that TP-Link is possibly using a custom Lua VM with modified opcodes or bytecode format, aand it's not that we are using the wrong Lua version.

Now, I'm not super experienced with Lua internals and it's been a while since I've done IoT reverse engineering. So I took to the internet looking for resources that can help me out. Thankfully someone else ran into the same issue as me and documented their solution in "[Unscrambling Lua](https://vovohelo.medium.com/unscrambling-lua-7bccb3d5660)".

Within their post, they referenced another article "[Decompile Lua bytecode of OpenWRT](https://web.archive.org/web/20210728101404/https://blog.ihipop.info/2018/05/5110.html)", where the author states:

> The default bytecode structure of the original Lua differs from that of OpenWrt. Therefore, the original Lua engine cannot be used for interpretation, resulting in errors such as "bad header in precompiled chunk".

Well that's the exact issue that we are having! Since TP-Link's firmware is based on OpenWRT (which modifies Lua for embedded systems), we need to patch `luadec` with the [OpenWRT patches](https://github.com/openwrt/openwrt/tree/main/package/utils/lua/patches) to handle the modified bytecode format.

It seemed easy enough, but before blindly applying patches, I wanted to understand what they actually fixed. I dug into the Lua source code and found that the bytecode header is generated by the [`luaU_header()`](https://github.com/viruscamp/lua5/blob/cdcfa70f2f731409046374e797a62314b4924b77/src/lundump.c#L214) function in `lundump.c`:

```c
/*
* make header
*/
void luaU_header (char* h)
{
 int x=1;
 memcpy(h,LUA_SIGNATURE,sizeof(LUA_SIGNATURE)-1);
 h+=sizeof(LUA_SIGNATURE)-1;
 *h++=(char)LUAC_VERSION;
 *h++=(char)LUAC_FORMAT;
 *h++=(char)*(char*)&x;				/* endianness */
 *h++=(char)sizeof(int);
 *h++=(char)sizeof(size_t);
 *h++=(char)sizeof(Instruction);
 *h++=(char)sizeof(lua_Number);
 *h++=(char)(((lua_Number)0.5)==0);		/* is lua_Number integral? */
}
```

As we can see `lua_Number` is the last byte of the header that represents the number type. By cross referencing that with the OpenWrt patches I noticed that this was modified within `010-lua-5.1.3-lnum-full-260308.patch`. 

```diff
- *h++=(char)(((lua_Number)0.5)==0);		/* is lua_Number integral? */
+ /* 
+  * Last byte of header (0/1 in unpatched Lua 5.1.3):
+  *
+  * 0: lua_Number is float or double, lua_Integer not used. (nonpatched only)
+  * 1: lua_Number is integer (nonpatched only)
+  *
+  * +2: LNUM_INT16: sizeof(lua_Integer)
+  * +4: LNUM_INT32: sizeof(lua_Integer)
+  * +8: LNUM_INT64: sizeof(lua_Integer)
+  *
+  * +0x80: LNUM_COMPLEX
+  */
+ *h++ = (char)(sizeof(lua_Integer)
+#ifdef LNUM_COMPLEX
+    | 0x80
+#endif
+    );
```

Perfect, so this will actually fix the header issue! This patch modifies the header generation to use `sizeof(lua_Integer)` instead of checking if `lua_Number` is integral. That explains the `04` we're seeing - it's indicating a 32-bit integer type.

## Building Patched Luadec

Thankfully for us, the author included instructions on how to apply the patches to Lua, and explained the additional changes that needed to be made to the Makefile as well. 

Using all the information provided, we can apply all the relevant OpenWrt patches and compile `luadec` step-by-step like so:

```bash
sudo apt-get update
sudo apt-get install -y libncurses-dev libreadline-dev build-essential

git clone https://github.com/viruscamp/luadec
cd luadec
git submodule update --init lua-5.1

ref=master
patch_dir=patches.$ref
mkdir $patch_dir && cd $patch_dir

patchs=$(curl -sSL -H 'Accept: application/vnd.github.v3+json' \
  'https://api.github.com/repos/openwrt/openwrt/contents/package/utils/lua/patches?ref='"$ref" \
  | grep -oP 'name"\s*:\s*".*\.patch' | grep -oP '\d+.*\.patch')

for p in $patchs; do
  wget "https://raw.githubusercontent.com/openwrt/openwrt/$ref/package/utils/lua/patches/$p" -O $p
done

cd ../lua-5.1

for i in ../${patch_dir}/*.patch; do
  patch -p1 < $i
done

MAKEFILE="src/Makefile"
cp "$MAKEFILE" "$MAKEFILE.bak"
sed -i '/# USE_READLINE=1/a PKG_VERSION = 5.1.5' "$MAKEFILE"
sed -i 's/CFLAGS= -O2 -Wall $(MYCFLAGS)/CFLAGS= -fPIC -O2 -Wall $(MYCFLAGS)/' "$MAKEFILE"
sed -i 's/$(CC) -o $@ -L\. -llua $(MYLDFLAGS) $(LUA_O) $(LIBS)/$(CC) -o $@ $(LUA_O) $(MYLDFLAGS) -L. -llua $(LIBS)/' "$MAKEFILE"
sed -i 's/$(CC) -o $@ -L\. -llua $(MYLDFLAGS) $(LUAC_O) $(LIBS)/$(CC) -o $@ $(LUAC_O) $(MYLDFLAGS) -L. -llua $(LIBS)/' "$MAKEFILE"

cd src
make linux
export LD_LIBRARY_PATH=$(pwd):$LD_LIBRARY_PATH

cd ../../luadec
make LUAVER=5.1
```

Once the build completed, I eagerly tried decompiling the login controller again:

```shell
$ luadec extracted/squashfs-root/usr/lib/lua/luci/controller/login.lua
luadec: extracted/squashfs-root/usr/lib/lua/luci/controller/login.lua: bad code in precompiled chunk
```

Okay, so we're making some progress now! We are successfully parsing the header, but are now getting a "bad code" error which means the bytecode instructions themselves don't match what `luadec` expects.

As a side note, the author of  "[Unscrambling Lua](https://vovohelo.medium.com/unscrambling-lua-7bccb3d5660)"  had encountered the same error, and noted that TP-Link was using instruction swapping in the Lua bytecode, where instead of `RETURN` they were calling `CLOSE`.

**TL;DR**: I tried running their deobfuscation script, but it failed in several places. After wasting more time than I'd like to admit trying to debug it, I concluded that either the script had bugs or TP-Link changed their obfuscation scheme between firmware versions.

Two steps forward, one step back. At this point I decided to do some more thorough research and look for some blogs on any exploits that targeted TP-Link's Lua code, all in the hopes that someone encountered the same issue as me. 

This led me to discovering Axel Souchet's ([0vercl0k](https://x.com/0vercl0k)) blog post "[Competing in Pwn2Own 2021 Austin: Icarus at the Zenith](https://doar-e.github.io/blog/2022/03/26/competing-in-pwn2own-2021-austin-icarus-at-the-zenith/)" where he was targeting the TP-Link AC1750 Smart Wi-Fi. While reading the blog, I came across this gem within his post:

> But interestingly enough, all the existing public Lua tooling failed at analyzing those extensions which was both frustrating and puzzling. Long story short, it seems like the Lua runtime used on the router has been modified such that the opcode table appears shuffled. As a result, the compiled extensions would break all the public tools because the opcodes wouldn't match.

Well that's quite interesting, and would explain why we got past the header validation but still hit the "bad code in precompiled chunk" error. TP-Link literally reordered the instruction definitions in their Lua VM. So when `luadec` reads bytecode instruction `0x05` and thinks "that's `OP_ADD`", TP-Link's VM interprets it as something completely different like `OP_MOVE`. It's basically a substitution cipher applied to the entire instruction set.

Unfortunately for us, this means we need to reverse engineer the Lua binaries within the firmware to extract the real opcode mapping... or so I thought until I read another piece of valuable information from Axel's post:

> One another thing I burned time on is to go through the GPL code archive that TP-Link published for this router: `ArcherC7V5.tar.bz2`. Because of licensing, TP-Link has to (?) 'maintain' an archive containing the GPL code they are using on the device.

Alex is right, with GPL code, if you use it in your product, you're legally required to make your modifications available. Since TP-Link uses OpenWRT as the base for their router firmware, they have to publish the source code they modified - just as with their encryption! This is exactly what we need!

## Investigating Shuffled Opcodes

Upon looking at TP-Links page, I found that they host the [Archer AX1800 V5.60 GPL Code](https://static.tp-link.com/upload/gpl-code/2025/202510/20251021/GPL_AX1800v5.tar.gz) under the routers support page. Since we have the GPL code then we don't need to reverse engineer the Lua binaries at all!

```shell
$ wget https://static.tp-link.com/upload/gpl-code/2025/202510/20251021/GPL_AX1800v5.tar.gz 
$ tar -xzf GPL_AX1800v5.tar.gz 
```

So the strategy is pretty simple here, since we already applied OpenWrt's patches to `luadec`, we can just diff TP-Link's GPL Lua code directly against our patched `luadec/lua-5.1` directory. This should isolate only TP-Link's custom modifications without all the noise from the OpenWRT patches we already applied.

Now, we need to find where the opcode definitions are located. Upon some digging it seems that the `lopcodes.h` and `lopcodes.c` files are responsible for housing this logic. So let's look for that file within the GPL code.

```shell
$ find . -name "*lopcodes*" -type f
./Iplatform/packages/opensource/xtables-addons/src-2.x/extensions/LUA/lua/lopcodes.h
./Iplatform/packages/opensource/xtables-addons/src-2.x/extensions/LUA/lua/lopcodes.c
./Iplatform/packages/opensource/xtables-addons/src-3.x/extensions/LUA/lua/lopcodes.h
./Iplatform/packages/opensource/xtables-addons/src-3.x/extensions/LUA/lua/lopcodes.c
./Iplatform/packages/opensource/xtables-addons/src/extensions/LUA/lua/lopcodes.h
./Iplatform/packages/opensource/xtables-addons/src/extensions/LUA/lua/lopcodes.c
./Iplatform/openwrt/ibase/lua/src/src/lopcodes.h
./Iplatform/openwrt/ibase/lua/src/src/lopcodes.c
./Iplatform/openwrt/ibase/lua/src-host/src/lopcodes.h
./Iplatform/openwrt/ibase/lua/src-host/src/lopcodes.c
```

Upon looking at this, we can assume that `./Iplatform/openwrt/ibase/lua/src/src/lopcodes.h` and `./Iplatform/openwrt/ibase/lua/src/src/lopcodes.c` are our files of interest. Let's diff the `lopcodes.h` file from the GPL code and our `luadec` to see what changes were made.

```diff
--- ../luadec/lua-5.1/src/lopcodes.h    2026-01-13 20:44:38.027965438 -0500
+++ ./Iplatform/openwrt/ibase/lua/src/src/lopcodes.h    2025-02-25 22:02:48.000000000 -0500
@@ -151,14 +151,8 @@
 /*----------------------------------------------------------------------
 name           args    description
 ------------------------------------------------------------------------*/
-OP_MOVE,/*     A B     R(A) := R(B)                                    */
-OP_LOADK,/*    A Bx    R(A) := Kst(Bx)                                 */
-OP_LOADBOOL,/* A B C   R(A) := (Bool)B; if (C) pc++                    */
-OP_LOADNIL,/*  A B     R(A) := ... := R(B) := nil                      */
-OP_GETUPVAL,/* A B     R(A) := UpValue[B]                              */
-
-OP_GETGLOBAL,/*        A Bx    R(A) := Gbl[Kst(Bx)]                            */
 OP_GETTABLE,/* A B C   R(A) := R(B)[RK(C)]                             */
+OP_GETGLOBAL,/*        A Bx    R(A) := Gbl[Kst(Bx)]                            */
 
 OP_SETGLOBAL,/*        A Bx    Gbl[Kst(Bx)] := R(A)                            */
 OP_SETUPVAL,/* A B     UpValue[B] := R(A)                              */
@@ -168,10 +162,19 @@
 
 OP_SELF,/*     A B C   R(A+1) := R(B); R(A) := R(B)[RK(C)]             */
 
-OP_ADD,/*      A B C   R(A) := RK(B) + RK(C)                           */
-OP_SUB,/*      A B C   R(A) := RK(B) - RK(C)                           */
-OP_MUL,/*      A B C   R(A) := RK(B) * RK(C)                           */
+OP_LOADNIL,/*  A B     R(A) := ... := R(B) := nil                      */
+OP_LOADK,/*    A Bx    R(A) := Kst(Bx)                                 */
+OP_LOADBOOL,/* A B C   R(A) := (Bool)B; if (C) pc++                    */
+OP_GETUPVAL,/* A B     R(A) := UpValue[B]                              */
+
+OP_LT,/*       A B C   if ((RK(B) <  RK(C)) ~= A) then pc++            */
+OP_LE,/*       A B C   if ((RK(B) <= RK(C)) ~= A) then pc++            */
+OP_EQ,/*       A B C   if ((RK(B) == RK(C)) ~= A) then pc++            */
+
 OP_DIV,/*      A B C   R(A) := RK(B) / RK(C)                           */
+OP_MUL,/*      A B C   R(A) := RK(B) * RK(C)                           */
+OP_SUB,/*      A B C   R(A) := RK(B) - RK(C)                           */
+OP_ADD,/*      A B C   R(A) := RK(B) + RK(C)                           */
 OP_MOD,/*      A B C   R(A) := RK(B) % RK(C)                           */
 OP_POW,/*      A B C   R(A) := RK(B) ^ RK(C)                           */
 OP_UNM,/*      A B     R(A) := -R(B)                                   */
@@ -182,16 +185,9 @@
 
 OP_JMP,/*      sBx     pc+=sBx                                 */
 
-OP_EQ,/*       A B C   if ((RK(B) == RK(C)) ~= A) then pc++            */
-OP_LT,/*       A B C   if ((RK(B) <  RK(C)) ~= A) then pc++            */
-OP_LE,/*       A B C   if ((RK(B) <= RK(C)) ~= A) then pc++            */
-
 OP_TEST,/*     A C     if not (R(A) <=> C) then pc++                   */ 
 OP_TESTSET,/*  A B C   if (R(B) <=> C) then R(A) := R(B) else pc++     */ 
-
-OP_CALL,/*     A B C   R(A), ... ,R(A+C-2) := R(A)(R(A+1), ... ,R(A+B-1)) */
-OP_TAILCALL,/* A B C   return R(A)(R(A+1), ... ,R(A+B-1))              */
-OP_RETURN,/*   A B     return R(A), ... ,R(A+B-2)      (see note)      */
+OP_MOVE,/*     A B     R(A) := R(B)                                    */
 
 OP_FORLOOP,/*  A sBx   R(A)+=R(A+2);
                        if R(A) <?= R(A+1) then { pc+=sBx; R(A+3)=R(A) }*/
@@ -204,6 +200,10 @@
 OP_CLOSE,/*    A       close all variables in the stack up to (>=) R(A)*/
 OP_CLOSURE,/*  A Bx    R(A) := closure(KPROTO[Bx], R(A), ... ,R(A+n))  */
 
+OP_CALL,/*     A B C   R(A), ... ,R(A+C-2) := R(A)(R(A+1), ... ,R(A+B-1)) */
+OP_RETURN,/*   A B     return R(A), ... ,R(A+B-2)      (see note)      */
+OP_TAILCALL,/* A B C   return R(A)(R(A+1), ... ,R(A+B-1))              */
+
 OP_VARARG/*    A B     R(A), R(A+1), ..., R(A+B-1) = vararg            */
 } OpCode;
 
@@ -243,8 +243,8 @@
 */  
 
 enum OpArgMask {
-  OpArgN,  /* argument is not used */
   OpArgU,  /* argument is used */
+  OpArgN,  /* argument is not used */
   OpArgR,  /* argument is a register or a jump offset */
   OpArgK   /* argument is a constant or register/constant */
 };
```

Upon inspecting the diff, we can clearly see that TP-Link did in fact shuffle the opcode table. Essentially by doing this, they reorder the `enum` table, breaking `luadec`. For example, `OP_MOVE` was the first opcode (index 0) in standard Lua, but now `OP_GETTABLE` occupies that position.

Now, this is probably not the only change that they made. For example, the `lcode.h` and `lcode.c` files are responsible for the code generation in Lua. And since we were getting a "bad code" error, it would be a good idea to take a peek at these as well. 

```diff
--- ../luadec/lua-5.1/src/lcode.h       2026-01-13 20:44:44.608673433 -0500
+++ ./Iplatform/openwrt/ibase/lua/src/src/lcode.h       2025-02-25 22:02:48.000000000 -0500
@@ -24,16 +24,16 @@
 ** grep "ORDER OPR" if you change these enums
 */
 typedef enum BinOpr {
-  OPR_ADD, OPR_SUB, OPR_MUL, OPR_DIV, OPR_MOD, OPR_POW,
-  OPR_CONCAT,
+  OPR_MOD, OPR_MUL, OPR_DIV, OPR_POW, OPR_SUB, OPR_ADD,
   OPR_NE, OPR_EQ,
-  OPR_LT, OPR_LE, OPR_GT, OPR_GE,
+  OPR_CONCAT,
   OPR_AND, OPR_OR,
+  OPR_LT, OPR_LE, OPR_GT, OPR_GE,
   OPR_NOBINOPR
 } BinOpr;
 
 
-typedef enum UnOpr { OPR_MINUS, OPR_NOT, OPR_LEN, OPR_NOUNOPR } UnOpr;
+typedef enum UnOpr { OPR_NOT, OPR_MINUS, OPR_LEN, OPR_NOUNOPR } UnOpr;
 
 
 #define getcode(fs,e)  ((fs)->f->code[(e)->u.s.info])
```

Of course when we inspect both files we'll clearly notice that TP-Link went ahead and shuffled these enums too. The `BinOpr` enum (binary operators) and `UnOpr` enum (unary operators) have both been reordered. In standard Lua the binary operators start with `OPR_ADD, OPR_SUB, OPR_MUL`, but TP-Link changed it to `OPR_MOD, OPR_MUL, OPR_DIV`. Same deal with unary operators, `OPR_MINUS` was first, now it's `OPR_NOT`. 

## Applying TP-Link's Modifications

This is great - but there are probably more files that are modified. Instead of playing whack-a-mole trying to find every file they modified, let's use a command to find all the files TP-Link modified by doing a comprehensive diff and then copying those files over to our `luadec` source folder.

```shell
$ diff -qr GPL_AX1800v5/Iplatform/openwrt/ibase/lua/src/src/ luadec/lua-5.1/src/ | grep "differ$" | awk '{print $2}' | sed 's|GPL_AX1800v5/Iplatform/openwrt/ibase/lua/src/src/||' | while read file; do cp "GPL_AX1800v5/Iplatform/openwrt/ibase/lua/src/src/$file" "luadec/lua-5.1/src/$file"; done
```

After doing this, we need to rebuild Lua 5.1 and `luadec` with these TP-Link modifications. To make this easier for future reference (and for anyone else who needs to do this), I wrote a script that automates the entire process: [luadec-tplink-compile.sh](https://gist.github.com/jhalon/97d5d14aa4554bb7df555e6261ef867c).

Running the script handles everything - cloning repos, applying patches, and compiling:

```shell
$ ./luadec-tplink-compile.sh                                                       ==================================
Building luadec with OpenWRT + TP-Link patches
==================================
[1/8] Installing dependencies...
[2/8] Cloning luadec repository...
[3/8] Initializing lua-5.1 submodule...
[4/8] Downloading OpenWRT Lua patches...
      > Found 14 patches
[5/8] Applying OpenWRT patches...
[6/8] Downloading TP-Link GPL code...
      > Downloading archive...
      > Extracting archive...
      > Applying TP-Link modifications...
      > Patching 21 modified files
[7/8] Compiling lua-5.1...
[8/8] Compiling luadec...

==================================
Build complete!
==================================

luadec binary: /home/kali/tplink/luadec/luadec/luadec

Test with:
  ./luadec /path/to/tplink/file.lua
```

With our now properly patched `luadec`, let's try decompiling that login controller one more time:

```lua
$ ./luadec ../../extracted/squashfs-root/usr/lib/lua/luci/controller/login.lua
-- Decompiled using luadec 2.2 rev: 895d923 for Lua 5.1 from https://github.com/viruscamp/luadec
-- Command line: ../../extracted/squashfs-root/usr/lib/lua/luci/controller/login.lua 

... snip of errors ...

-- params : ...
-- function num : 0
module("luci.controller.login", package.seeall)
local l_0_0 = require("luci.model.controller")
local l_0_1 = require("nixio")
local l_0_2 = require("nixio.fs")
local l_0_3 = require("luci.sys")
local l_0_4 = require("luci.util")
local l_0_5 = require("luci.model.passwd_recovery")
local l_0_6 = require("luci.tools.debug")
local l_0_7 = (require("luci.ltn12"))
local l_0_8 = nil
local l_0_9 = "/var/run/luci-attempts.lock"
local l_0_10 = "/tmp/luci-attempts"
local l_0_11 = Unknown_Type_Error
local l_0_12 = Unknown_Type_Error
local l_0_13 = Unknown_Type_Error
local l_0_14 = require("luci.model.accountmgnt")
local l_0_15 = ((require("luci.model.asycrypto")).Crypto)("rsa")
local l_0_16 = require("luci.model.uci")
local l_0_17 = (l_0_16.cursor)()
local l_0_18 = require("luci.service")
local l_0_19 = require("luci.model.log")
local l_0_20 = "/tmp/auto_update_lock.lua"
local l_0_21 = "/usr/sbin/cloud_setupTMHomecare"
local l_0_22 = require("luci.controller.admin.onemesh")
local l_0_23 = Unknown_Type_Error
local l_0_24 = Unknown_Type_Error
local l_0_30 = function(l_1_0)
  -- function num : 0_0 , upvalues : l_0_8, l_0_1, l_0_9
  l_0_8 = (l_0_1.open)(l_0_9, "w", Unknown_Type_Error)
  l_0_8:flock(l_1_0 and "ex" or "sh")
end
```

Success! Well... mostly. The decompiler still throws some errors and there are `Unknown_Type_Error` placeholders scattered throughout. But you know what, the disassembly works perfectly, and that's pretty much all that we need for reverse engineering:

```lua
$ ./luadec -dis ../../extracted/squashfs-root/usr/lib/lua/luci/controller/login.lua 
; Disassembled using luadec 2.2 rev: 895d923 for Lua 5.1 from https://github.com/viruscamp/luadec
; Command line: -dis ../../extracted/squashfs-root/usr/lib/lua/luci/controller/login.lua 

; Function:        0
; Defined at line: 0
; #Upvalues:       0
; #Parameters:     0
; Is_vararg:       2
; Max Stack Size:  35

    0 [-]: GETGLOBAL R0 K0        ; R0 := module
    1 [-]: LOADK     R1 K1        ; R1 := "luci.controller.login"
    2 [-]: GETGLOBAL R2 K2        ; R2 := package
    3 [-]: GETTABLE  R2 R2 K3     ; R2 := R2["seeall"]
    4 [-]: CALL      R0 3 1       ;  := R0(R1 to R2)
    5 [-]: GETGLOBAL R0 K4        ; R0 := require
    6 [-]: LOADK     R1 K5        ; R1 := "luci.model.controller"
    7 [-]: CALL      R0 2 2       ; R0 := R0(R1)
    8 [-]: GETGLOBAL R1 K4        ; R1 := require
    9 [-]: LOADK     R2 K6        ; R2 := "nixio"
   10 [-]: CALL      R1 2 2       ; R1 := R1(R2)
   11 [-]: GETGLOBAL R2 K4        ; R2 := require
   12 [-]: LOADK     R3 K7        ; R3 := "nixio.fs"
   13 [-]: CALL      R2 2 2       ; R2 := R2(R3)
   14 [-]: GETGLOBAL R3 K4        ; R3 := require
   15 [-]: LOADK     R4 K8        ; R4 := "luci.sys"
   16 [-]: CALL      R3 2 2       ; R3 := R3(R4)
   17 [-]: GETGLOBAL R4 K4        ; R4 := require
   18 [-]: LOADK     R5 K9        ; R5 := "luci.util"
   19 [-]: CALL      R4 2 2       ; R4 := R4(R5)
   20 [-]: GETGLOBAL R5 K4        ; R5 := require
   21 [-]: LOADK     R6 K10       ; R6 := "luci.model.passwd_recovery"
   22 [-]: CALL      R5 2 2       ; R5 := R5(R6)
   23 [-]: GETGLOBAL R6 K4        ; R6 := require
   24 [-]: LOADK     R7 K11       ; R7 := "luci.tools.debug"
   25 [-]: CALL      R6 2 2       ; R6 := R6(R7)
   26 [-]: GETGLOBAL R7 K4        ; R7 := require
   27 [-]: LOADK     R8 K12       ; R8 := "luci.ltn12"
   28 [-]: CALL      R7 2 2       ; R7 := R7(R8)
   29 [-]: LOADNIL   R8 R8        ; R8 := nil
   30 [-]: LOADK     R9 K13       ; R9 := "/var/run/luci-attempts.lock"
   31 [-]: LOADK     R10 K14      ; R10 := "/tmp/luci-attempts"
   32 [-]: LOADK     R11 K15      ; R11 := Unknown_Type_Error
   33 [-]: LOADK     R12 K16      ; R12 := Unknown_Type_Error
   34 [-]: LOADK     R13 K17      ; R13 := Unknown_Type_Error
   35 [-]: GETGLOBAL R14 K4       ; R14 := require
   36 [-]: LOADK     R15 K18      ; R15 := "luci.model.accountmgnt"
   37 [-]: CALL      R14 2 2      ; R14 := R14(R15)
   38 [-]: GETGLOBAL R15 K4       ; R15 := require
   39 [-]: LOADK     R16 K19      ; R16 := "luci.model.asycrypto"
   40 [-]: CALL      R15 2 2      ; R15 := R15(R16)
   41 [-]: GETTABLE  R15 R15 K20  ; R15 := R15["Crypto"]
   42 [-]: LOADK     R16 K21      ; R16 := "rsa"
   43 [-]: CALL      R15 2 2      ; R15 := R15(R16)
   44 [-]: GETGLOBAL R16 K4       ; R16 := require
   45 [-]: LOADK     R17 K22      ; R17 := "luci.model.uci"
   46 [-]: CALL      R16 2 2      ; R16 := R16(R17)
   47 [-]: GETTABLE  R17 R16 K23  ; R17 := R16["cursor"]
   48 [-]: CALL      R17 1 2      ; R17 := R17()
   49 [-]: GETGLOBAL R18 K4       ; R18 := require
   50 [-]: LOADK     R19 K24      ; R19 := "luci.service"
```

The disassembly now gives us complete visibility into the control flow and logic. Combined with the partial decompilation (even with its quirks), we now have everything we need to analyze the firmware for vulnerabilities.
## Wrapping Up

And that about wraps it up! Now that we can decompile the Lua backend, the real fun begins - actually looking for vulnerabilities in the router's backend server logic. But that's a story for another coffee-fueled blog post.

If you want to replicate this process, grab the [luadec-tplink-compile.sh]([https://gist.github.com/example](https://gist.github.com/jhalon/97d5d14aa4554bb7df555e6261ef867c)) script and have at it. And if you find something interesting in TP-Link's firmware or find a bug in the Lua code because of this, I'd love to hear about it! 