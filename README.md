# LDAP authentication plugin for StackStorm Community edition

[![Build Status](https://api.travis-ci.org/StackStorm/st2-auth-backend-ldap.svg?branch=master)](https://travis-ci.org/StackStorm/st2-auth-backend-ldap) [![IRC](https://img.shields.io/irc/%23stackstorm.png)](http://webchat.freenode.net/?channels=stackstorm)

The LDAP backend reads credentials and authenticates user against an LDAP server. This backend
was originally contributed to st2 repo by [Ruslan Tumarkin](https://github.com/ruslantum) under
[PR #1790](https://github.com/StackStorm/st2/pull/1790).

Note:

Currently there are two types of LDAP backends available - community contributed one and one
developed and maintained by the StackStorm team. This repository contains a community contributed
one.

Community contributed backend can be installed by anyone and the StackStorm developed one is only
available in the enterprise edition (for more information on the enterprise edition, please see
https://stackstorm.com/product/#enterprise).

The difference between them is that the one included in the enterprise edition is developed,
supported, tested, maintained and certified by the StackStorm team and the community contributed
one is developed and maintained by the community.

### Dependencies

```
yum install openldap-devel -y
```

### Configuration Options

| option        | required | default | description                                                |
|---------------|----------|---------|------------------------------------------------------------|
| ldap_server   | yes      |         | URL of the LDAP server                                     |
| domain        | yes      |         | Users' email domain                                        |
| use_tls       | yes      |         | Boolean parameter to set if tls is required                |

### Configuration Example

Please refer to the authentication section in the StackStorm
[documentation](http://docs.stackstorm.com) for basic setup concept. The
following is an example of the auth section in the StackStorm configuration file for the flat-file
backend.

```
[auth]
mode = standalone
backend = ldap
backend_kwargs = {"ldap_server": "ldap://identity.example.com:389", "domain": "stackstorm.com", "use_tls": true}
enable = True
use_ssl = True
cert = /path/to/ssl/cert/file
key = /path/to/ssl/key/file
logging = /path/to/st2auth.logging.conf
api_url = https://myhost.example.com:9101
debug = False
```

## Copyright, License, and Contributors Agreement

Copyright 2015 StackStorm, Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this work except in
compliance with the License. You may obtain a copy of the License in the [LICENSE](LICENSE) file,
or at: [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

By contributing you agree that these contributions are your own (or approved by your employer) and 
you grant a full, complete, irrevocable copyright license to all users and developers of the
project, present and future, pursuant to the license of the project.
