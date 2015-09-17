
Home Automation On The Cheap
===================================

The initial attempts to reach Arduino over WiFi were unsuccessful due to CC3000 instability. The WiFi module was replaced with a plain cable Ethernet W5100 and now it works! 

The commands are delivered to Arduino over http and they are authenticated with a nonce and the HMAC-SHA256. There are 2 clients already - one as a Chrome extension, and the other one as an Android apk.

In the neighbour repository of mine, there is an Android client which reaches Arduino over the Bluetooth.

