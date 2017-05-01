# Licensed to the StackStorm, Inc ('StackStorm') under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import ldap
import os
import unittest2
from mockldap import MockLdap
from st2auth_ldap_backend.ldap_backend import LDAPAuthenticationBackend

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

class LDAPAuthenticationBackendTestCase(unittest2.TestCase):
    """
    A simple test case showing off some of the basic features of mockldap.
    """
    connect_methods = ['initialize', 'set_option', 'set_option']

    directory = {
        'dc=com': {'dc': ['com']},
        'dc=example,dc=com': {'dc': ['example']},
        'ou=users,dc=example,dc=com': {'ou': ['users'], 'objectClass': ['groupOfNames'], 'member': ['uid=sarah_connor,ou=users,dc=example,dc=com', 'uid=john_connor,ou=users,dc=example,dc=com']},
        'cn=manager,dc=example,dc=com': {'cn': ['manager'], 'userPassword': ['ldaptest']},
        'uid=sarah_connor,ou=users,dc=example,dc=com': { 'uid': ['sarah_connor'], 'userPassword': ['Reece4ever'], 'objectclass': ['inetOrgPerson', 'posixAccount', 'person', 'top'] },
        'uid=john_connor,ou=users,dc=example,dc=com': { 'uid': ['john_connor'], 'userPassword': ['HastaLavista'], 'objectclass': ['inetOrgPerson', 'posixAccount', 'person', 'top'] },
        'cn=resistance,ou=groups,dc=example,dc=com': { 'cn': ['resistance'], 'description': ['memberOf'], 'memberuid': ['sarah_connor', 'john_connor'], 'objectclass': ['posixGroup', 'top']}
    }


    @classmethod
    def setUpClass(cls):
        # We only need to create the MockLdap instance once. The content we
        # pass in will be used for all LDAP connections.
        cls.mockldap = MockLdap(cls.directory)


    @classmethod
    def tearDownClass(cls):
        del cls.mockldap

    def setUp(self):
        # Patch ldap.initialize
        self.mockldap.start()
        self.ldapobj = self.mockldap['ldap://fakeldap.example.com/']

    def tearDown(self):
        # Stop patching ldap.initialize and reset state.
        self.mockldap.stop()
        del self.ldapobj


    def test_bind_anonymous(self):
        result = _do_simple_bind('ldap://fakeldap.example.com/', '', '')

        self.assertEquals(self.ldapobj.methods_called(), self.connect_methods + ['simple_bind_s', 'whoami_s', 'unbind'])
        self.assertTrue(result)


    def test_bind_dn_valid(self):
        result = _do_simple_bind('ldap://fakeldap.example.com/', 'cn=manager,dc=example,dc=com', 'ldaptest')

        self.assertEquals(self.ldapobj.methods_called(), self.connect_methods + ['simple_bind_s', 'whoami_s', 'unbind'])
        self.assertTrue(result)


    def test_bind_dn_invalid_user(self):
        result = _do_simple_bind('ldap://fakeldap.example.com/', 'uid=invalid_user,ou=users,dc=example,dc=com', 'none')

        self.assertEquals(self.ldapobj.methods_called(), self.connect_methods + ['simple_bind_s', 'unbind'])
        self.assertFalse(result)


    def test_bind_dn_invalid_password(self):
        result = _do_simple_bind('ldap://fakeldap.example.com/', 'cn=manager,dc=example,dc=com', 'invalid_password')

        self.assertEquals(self.ldapobj.methods_called(), self.connect_methods + ['simple_bind_s', 'unbind'])
        self.assertFalse(result)

    def test_search_valid_username(self):
        username = 'sarah_connor'
        password = 'Reece4ever'
        user_dn = 'uid={},ou=users,dc=example,dc=com'.format(username)

        mock_res = (user_dn, LDAPAuthenticationBackendTestCase.directory[user_dn])

        user = {"base_dn": "ou=users,dc=example,dc=com", "search_filter": "(uid={username})", "scope": "onelevel"}

        self.ldapobj.search_s.seed(user["base_dn"], ldap.SCOPE_ONELEVEL, user["search_filter"].format(username=username))([mock_res])

        result = _do_simple_bind('ldap://fakeldap.example.com/', 'cn=manager,dc=example,dc=com', 'ldaptest', user_search=user, group_search=None, username=username, password=password)

        expected_methods_called = (
            self.connect_methods +
            ['simple_bind_s', 'whoami_s', 'search_s'] +
            self.connect_methods +
            ['simple_bind_s', 'whoami_s', 'unbind', 'unbind']
        )

        self.assertEquals(self.ldapobj.methods_called(), expected_methods_called)
        self.assertTrue(result)

    def test_search_invalid_username(self):
        username = 'invalid_username'
        password = 'Reece4ever'
        user = {"base_dn": "ou=users,dc=example,dc=com", "search_filter": "(uid={username})", "scope": "onelevel"}

        mock_res = []

        self.ldapobj.search_s.seed(user["base_dn"], ldap.SCOPE_ONELEVEL, user["search_filter"].format(username=username))(mock_res)
        result = _do_simple_bind('ldap://fakeldap.example.com/', 'cn=manager,dc=example,dc=com', 'ldaptest', user_search=user, group_search=None, username=username, password=password)

        expected_methods_called = (
            self.connect_methods +
            ['simple_bind_s', 'whoami_s', 'search_s', 'unbind']
        )

        self.assertEquals(self.ldapobj.methods_called(), expected_methods_called)
        self.assertFalse(result)

    def test_search_invalid_password(self):
        username = 'sarah_connor'
        password = 'bad_password'
        user = {"base_dn": "ou=users,dc=example,dc=com", "search_filter": "(uid={username})", "scope": "onelevel"}

        mock_res = []

        self.ldapobj.search_s.seed(user["base_dn"], ldap.SCOPE_ONELEVEL, user["search_filter"].format(username=username))(mock_res)
        result = _do_simple_bind('ldap://fakeldap.example.com/', 'cn=manager,dc=example,dc=com', 'ldaptest', user_search=user, group_search=None, username=username, password=password)

        expected_methods_called = (
            self.connect_methods +
            ['simple_bind_s', 'whoami_s', 'search_s', 'unbind']
        )

        self.assertEquals(self.ldapobj.methods_called(), expected_methods_called)
        self.assertFalse(result)

    def test_search_valid_username_valid_group(self):
        username = 'john_connor'
        password = 'HastaLavista'
        user_dn = 'uid={},ou=users,dc=example,dc=com'.format(username)
        mock_user_res = (user_dn, LDAPAuthenticationBackendTestCase.directory[user_dn])

        groupname = 'resistance'
        group_dn = 'cn={groupname},ou=groups,dc=example,dc=com'.format(groupname=groupname)
        mock_group_res = (group_dn, LDAPAuthenticationBackendTestCase.directory[group_dn])

        user = {"base_dn": "ou=users,dc=example,dc=com", "search_filter": "(uid={username})", "scope": "onelevel"}
        group = {"base_dn": "ou=groups,dc=example,dc=com", "search_filter": "(&(cn=%s)(memberUid={username}))"%groupname, "scope": "subtree"}

        self.ldapobj.search_s.seed(user["base_dn"], ldap.SCOPE_ONELEVEL, user["search_filter"].format(username=username))([mock_user_res])
        self.ldapobj.search_s.seed(group["base_dn"], ldap.SCOPE_SUBTREE, group["search_filter"].format(username=username))([mock_group_res])

        result = _do_simple_bind('ldap://fakeldap.example.com/', 'cn=manager,dc=example,dc=com', 'ldaptest', user_search=user, group_search=group, username=username, password=password)

        expected_methods_called = (
            self.connect_methods +
            ['simple_bind_s', 'whoami_s', 'search_s'] +
            self.connect_methods +
            ['simple_bind_s', 'whoami_s', 'unbind', 'search_s', 'unbind']
        )

        self.assertEquals(self.ldapobj.methods_called(), expected_methods_called)
        self.assertTrue(result)

    def test_search_valid_username_invalid_group(self):
        username = 'john_connor'
        password = 'HastaLavista'
        user_dn = 'uid={},ou=users,dc=example,dc=com'.format(username)
        mock_user_res = (user_dn, LDAPAuthenticationBackendTestCase.directory[user_dn])

        groupname = 'invalid_group'
        group_dn = 'cn={groupname},ou=groups,dc=example,dc=com'.format(groupname=groupname)
        mock_group_res = []

        user = {"base_dn": "ou=users,dc=example,dc=com", "search_filter": "(uid={username})", "scope": "onelevel"}
        group = {"base_dn": "ou=groups,dc=example,dc=com", "search_filter": "(&(cn=%s)(memberUid={username}))"%groupname, "scope": "subtree"}

        self.ldapobj.search_s.seed(user["base_dn"], ldap.SCOPE_ONELEVEL, user["search_filter"].format(username=username))([mock_user_res])
        self.ldapobj.search_s.seed(group["base_dn"], ldap.SCOPE_SUBTREE, group["search_filter"].format(username=username))(mock_group_res)

        result = _do_simple_bind('ldap://fakeldap.example.com/', 'cn=manager,dc=example,dc=com', 'ldaptest', user_search=user, group_search=group, username=username, password=password)

        expected_methods_called = (
            self.connect_methods +
            ['simple_bind_s', 'whoami_s', 'search_s'] +
            self.connect_methods + 
            ['simple_bind_s', 'whoami_s', 'unbind', 'search_s', 'unbind']
        )

        self.assertEquals(self.ldapobj.methods_called(), expected_methods_called)
        self.assertFalse(result)


def _do_simple_bind(uri, bind_dn, bind_pw, user_search=None, group_search=None, username=None, password=None):
    backend = LDAPAuthenticationBackend(uri, use_tls=False, bind_dn=bind_dn, bind_pw=bind_pw, user=user_search, group=group_search)
    return backend.authenticate(username, password)


if __name__ == '__main__':
    sys.exit(unittest2.main())
