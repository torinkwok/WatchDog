# WatchDog [![travis-ci-status](https://travis-ci.org/TorinKwok/WatchDog.svg?branch=master)](https://travis-ci.org/TorinKwok/WatchDog) [![license](https://img.shields.io/github/license/mashape/apistatus.svg)](./LICENSE) [![release](https://img.shields.io/github/release/TorinKwok/WatchDog.svg)](https://github.com/TorinKwok/WatchDog/releases)

### What's this?

[GateKeeper](https://en.wikipedia.org/wiki/Gatekeeper_(macOS)), [MRT (Malware Removal Tool)](https://support.apple.com/kb/PH25087?locale=en_US), and [XProtect](https://www.howtogeek.com/217043/xprotect-explained-how-your-macs-built-in-anti-malware-works/) are all built-in features of Mac OS designed to prevent malware threats and other nefarious software from being installed or used on a Mac. These security features exist in the background and are updated with regular system software updates to Mac OS, but Apple will also push quiet updates to xprotect or MRT to add new definitions and block newfound threats.

Advanced users may wish to know what versions of those security tools is installed on a Mac. *WatchDog* is a lovely script written for that.

```
$ ./watchdog.swift
Name                     Date                     Version     
---------------------------------------------------------
XProtect                 23 Feb 2017, 10:34 AM    2089        
Gatekeeper               11 Aug 2016, 10:08 AM    94          
SIP                      31 Jul 2016, 3:21 AM     14.0        
MRT                      15 Oct 2016, 10:57 AM    1.7.1       
Core Suggestions         08 Otc 2017  10:22 PM    788
Incompatible Kernel Ext. 18 Dec 2016, 8:54 AM     12.5.0     
Chinese Word List        13 Otc 2014  8:22 PM     4.22
Core LSKD (dkrl)         18 Feb 2017, 6:17 AM     8  
```

### Author
Torin Kwok.
