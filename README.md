DNSApi
===

The dns api is a simple api that allows requesting of axfr entries on a dns server, and adding/updating/removing entries with standard dns messages.

It uses a simple TSIG with keyname and base64 encoded key, only with hmac-md5 algo.
