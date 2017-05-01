# LDAP authentication plug-in for StackStorm Community edition

[![Build Status](https://api.travis-ci.org/StackStorm/st2-auth-backend-ldap.svg?branch=master)](https://travis-ci.org/StackStorm/st2-auth-backend-ldap) [![IRC](https://img.shields.io/irc/%23stackstorm.png)](http://webchat.freenode.net/?channels=stackstorm)

The LDAP backend reads credentials and authenticates users against an LDAP server. This backend was originally contributed to the st2 repo by [Ruslan Tumarkin](https://github.com/ruslantum) under [PR #1790](https://github.com/StackStorm/st2/pull/1790).

#### Note:
There are currently two types of LDAP backends available - community contributed one and one developed and maintained by the StackStorm team. This repository contains the community contributed one.

Community contributed backend can be installed by anyone and the StackStorm developed one is only available in the enterprise edition (for more information on the enterprise edition, please see https://stackstorm.com/product/#enterprise).

The difference between them is that the one included in the enterprise edition is developed, supported, tested, maintained and certified by the StackStorm team and the community contributed one is developed and maintained by the community.

### Configuration Options

| option          | required | default | description                                                |
|-----------------|----------|---------|------------------------------------------------------------|
| ldap_uri        | yes      |         | URI of the LDAP server.  Format: `<protocol>://<hostname>[:port] `(Protocol: `ldap` or `ldaps`) |
| use_tls         | yes      |  False  | Boolean parameter to set if tls is required. Should be set to *false* using _ldaps_ in the uri. |
| bind_dn         | no       |  ""     | DN user to bind to LDAP.  If an empty string, an anonymous bind is performed. To use the user supplied username in the bind_dn, use the `{username}` placeholder in string. |
| bind_pw         | no       |  ""     | DN password.  Use the `{password}` placeholder in the string to use the user supplied password.|
| user            | no       |  None   | Search parameters for user authentication. _see user table below_ |
| group           | no       |  None   | Search parameters for user's group membership. _see group table below_ |
| chase_referrals | no       |  True   | Boolean parameter to set whether to chase referrals. |

#### Attributes for user option
| option        | required | default | description                                                |
|---------------|----------|---------|------------------------------------------------------------|
| base_dn       | yes      |   n/a   | Base DN on the LDAP server to be used when looking up the user account. |
| search_filter | yes      |   n/a   | Should contain the placeholder `{username}` for the username. |
| scope         | yes      |   n/a  | The scope of the search to be performed. Available choices: _base_, _onelevel_, _subtree_ |

#### Attributes for group option
| option        | required | default | description                                                |
|---------------|----------|---------|------------------------------------------------------------|
| base_dn       | yes      |   n/a   | Base DN on the LDAP server to be used when looking up the group. |
| search_filter | yes      |   n/a   | Should contain the placeholder `{username}` for the username. |
| scope         | yes      |   n/a   | The scope of the search to be performed. Available choices: _base_, _onelevel_, _subtree_ |

### Configuration Example

Please refer to the authentication section in the StackStorm [documentation](http://docs.stackstorm.com) for basic setup concept. The following is an example of the auth section in the StackStorm configuration file for the ldap backend.

```[auth]
mode = standalone
backend = ldap
backend_kwargs = { "ldap_uri": "ldap://ldap.example.com", "use_tls": true, "bind_dn": "cn=user,dc=example,dc=com", "bind_pw": "bind_password", "user": {"base_dn": "ou=users,dc=example,dc=com", "search_filter": "(uid={username})", "scope": "onelevel"}, "group": {"base_dn": "ou=groups,dc=example,dc=com", "search_filter": "(&(cn=st2access)(memberUid={username}))", "scope": "subtree"} }
enable = True
use_ssl = True
cert = /path/to/ssl/cert/file
key = /path/to/ssl/key/file
logging = /path/to/st2auth.logging.conf
api_url = https://myhost.example.com:9101
debug = False
```

### Authenticating users against various schemas.

There is no one standard way to store user credentials in LDAP.  There are various ways to organise the directory tree and various ways to secure it.  In some cases, the users DN can't be determined with a static configuration and requires a bind DN to locate the user in the database before user authentication can occur.

This authentication backend attempts to be flexible with the way LDAP binding and authentication can be performed, but may not meet all use cases.

#### Active Directory Examples

Using `sAMAccountName` should be unique in combination with a domain name.
`"bind_dn": "sAMAccountName={username}@example.com", "bind_pw": "{password}"`

Using `userPrincipalName` should be unique within a forest.
`"bind_dn": "userPrincipalName={username}", "bind_pw": "{password}"`

#### OpenLDAP Examples

Using anonymous binding
`"bind_dn": "", "bind_pw": ""`

Using bind DN
`"bind_dn": "cn=bind_user,dc=example,dc=com", "bind_pw": "bind_user_password"`


### Installation

#### Production

1. Activate the StackStorm virtual environment.
 `source /<path to stackstorm>/st2/bin/activate`
2.  Install the LDAP plug-in and its dependencies.
 `pip install git+https://github.com/<github_account>/st2-auth-backend-ldap.git@master#egg=st2_auth_backend_ldap`
3. Configure the authentication backend in `/etc/st2/st2.conf` (see example above).
4. Restart StackStorm
 `st2ctl restart`

#### Development
Suitable for development environments and may not be ideal under production conditions.

 1. Activate the StackStorm virtual environment.
 `source /<path to stackstorm>/st2/bin/activate`
 2. Upgrade pip to the latest version.
 `pip install --update pip`
 3. Optionally, install dev packages for ldap
 `apt-get install libsasl2-dev python-dev libldap2-dev libssl-dev`
 4. Install the LDAP plug-in and its dependencies.
 `pip install git+https://github.com/<github_account>/st2-auth-backend-ldap.git@master#egg=st2_auth_backend_ldap`
 5. Deactivate virtual environment.
 `deactivate`
 6. Configure the authentication backend in `/etc/st2/st2.conf` (see example above).
 7. Restart StackStorm
 `st2ctl restart`


## Copyright, License, and Contributors Agreement

Copyright 2015 StackStorm, Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this work except in
compliance with the License. You may obtain a copy of the License in the [LICENSE](LICENSE) file,
or at: [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

By contributing you agree that these contributions are your own (or approved by your employer) and
you grant a full, complete, irrevocable copyright license to all users and developers of the
project, present and future, pursuant to the license of the project.
