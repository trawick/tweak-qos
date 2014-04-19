tweak-qos
=========

mod_qos 10.30 from Sourceforge plus some proposed fixes

contents
========

Only the apache2 subdirectory of mod_qos has been imported.  This is the module itself.

licensing
=========

The "real" mod_qos is GPLv2.  The licensing of any changes here is the same.

references
==========

* http://opensource.adnovum.ch/mod_qos/
* http://sourceforge.net/projects/mod-qos/
* https://sourceforge.net/p/mod-qos/discussion/697421/thread/957783bd/

using the new implementation
============================

Previously, you might configure bandwidth limiting like this (presumably with a more interesting criterium for the event):
```
SetEnvIf Request_URI "."  TESTING
QS_EventKBytesPerSecLimit TESTING 100
QS_EventPerSecLimit       TESTING 999999
QS_EventRequestLimit      TESTING 999999
```

(You need to configure more than just QS_EventKBytesPerSecLimit, even if you don't care about the other features.)

Now it is simply
```
SetEnvIf Request_URI "."  TESTING
QS_EventNewKBytesPerSecLimit TESTING 100
```

Checking that an environment variable is **not** set also works:
```
QS_EventNewKBytesPerSecLimit !TESTING 100
```

(In other words, limit download bandwidth to 100K bytes per second if the TESTING variable is **not** defined.)

VIP selection is also supported.  (VIPs won't be limited to the configured bandwidth.)

miscellaneous notes
===================

* If the response is relatively small compared with the limit (e.g., 50 byte response, 5K/second limit), the
configured bandwidth will be underutilized (by perhaps 5%).
