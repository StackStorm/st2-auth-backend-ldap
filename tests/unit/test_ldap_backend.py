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
import logging
import os
import re
import unittest2
import mock
from mockldap import MockLdap
from mockldap.recording import RecordedMethod
from st2auth_ldap_backend import ldap_backend
from st2auth_ldap_backend.ldap_backend import LDAPAuthenticationBackend

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_URI = 'ldap://fakeldap.example.com/'


class LDAPAuthenticationBackendTestCase(unittest2.TestCase):
    """
    A simple test case showing off some of the basic features of mockldap.
    """
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

        # needs decorator to record calling 'result' method
        self.mock_referral = []
        self.ldapobj._result = self.ldapobj.result

        # Note:
        # These side_effect mocks are stopgap measures until ldapmock module implements
        # the processing to get entries synchronously at the 'result' method.

        # extending 'result' method of ldapmock module to enables get objects synchronously
        def side_effect_result(*args, **kwargs):
            def result(ldapobj, msgid, all):
                if all:
                    # normal processing of mockldap
                    return (ldap.RES_SEARCH_RESULT, self._sync_results)
                else:
                    if self._sync_results:
                        return (ldap.RES_SEARCH_ENTRY, [self._sync_results.pop()])
                    elif self.mock_referral:
                        # when mock_referrals are defined, this returns referral object
                        return (ldap.RES_SEARCH_REFERENCE, [self.mock_referral.pop()])
                    else:
                        # the case of test that dereferences referral object
                        return (ldap.RES_SEARCH_RESULT, None)

            if self._sync_results == None:
                # get entry objects through the original 'result' method of ldapmock module
                self._sync_results = self.ldapobj._result(*args, **kwargs)[1]
                return result(self.ldapobj, *args, **kwargs)
            else:
                # call result method through RecordedMethod for tracking method calling of LDAPObject
                return RecordedMethod(result, self.ldapobj)(*args, **kwargs)
        self.ldapobj.result = mock.Mock(side_effect=side_effect_result)

        self.ldapobj._search = self.ldapobj.search
        def side_effect_search(*args, **kwargs):
            # clear the interal state of test 'result' method
            self._sync_results = None
            return self.ldapobj._search(*args, **kwargs)
        self.ldapobj.search = mock.Mock(side_effect=side_effect_search)

        class LogHandler(logging.StreamHandler):
            """Mock logging handler to check log output"""

            def __init__(self, *args, **kwargs):
                self.reset()
                logging.StreamHandler.__init__(self, *args, **kwargs)

            def emit(self, record):
                self.messages[record.levelname.lower()].append(record.getMessage())

            def reset(self):
                self.messages = {
                    'debug': [],
                    'info': [],
                    'warning': [],
                    'error': [],
                    'critical': [],
                }
        self.log_handler = LogHandler()

        # set LogHandler for checking log outputs
        ldap_backend.LOG.addHandler(self.log_handler)

    def tearDown(self):
        # Stop patching ldap.initialize and reset state.
        self.mockldap.stop()
        del self.ldapobj


    def test_bind_anonymous(self):
        result = _do_simple_bind('', '')

        self.assertEquals(self.ldapobj.methods_called(), ['initialize', 'simple_bind_s', 'whoami_s', 'unbind'])
        self.assertTrue(result)


    def test_bind_dn_valid(self):
        result = _do_simple_bind('cn=manager,dc=example,dc=com', 'ldaptest')

        self.assertEquals(self.ldapobj.methods_called(), ['initialize', 'simple_bind_s', 'whoami_s', 'unbind'])
        self.assertTrue(result)


    def test_bind_dn_invalid_user(self):
        result = _do_simple_bind('uid=invalid_user,ou=users,dc=example,dc=com', 'none')

        self.assertEquals(self.ldapobj.methods_called(), ['initialize', 'simple_bind_s', 'unbind'])
        self.assertFalse(result)


    def test_bind_dn_invalid_password(self):
        result = _do_simple_bind('cn=manager,dc=example,dc=com', 'invalid_password')

        self.assertEquals(self.ldapobj.methods_called(), ['initialize', 'simple_bind_s', 'unbind'])
        self.assertFalse(result)

    def test_search_valid_username(self):
        username = 'sarah_connor'
        password = 'Reece4ever'
        user_dn = 'uid={},ou=users,dc=example,dc=com'.format(username)

        mock_res = (user_dn, LDAPAuthenticationBackendTestCase.directory[user_dn])

        user = {"base_dn": "ou=users,dc=example,dc=com", "search_filter": "(uid={username})", "scope": "onelevel"}

        self.ldapobj.search_s.seed(user["base_dn"], ldap.SCOPE_ONELEVEL, user["search_filter"].format(username=username))([mock_res])

        result = _do_simple_bind('cn=manager,dc=example,dc=com', 'ldaptest', user_search=user, group_search=None, username=username, password=password)

        self.assertEquals(self.ldapobj.methods_called(), [
            'initialize',
            'simple_bind_s',
            'whoami_s',
            'search',
            'result',
            'result',
            'initialize',
            'simple_bind_s',
            'whoami_s',
            'unbind',
            'unbind'
            ]
        )
        self.assertTrue(result)


    def test_search_invalid_username(self):
        username = 'invalid_username'
        password = 'Reece4ever'
        user = {"base_dn": "ou=users,dc=example,dc=com", "search_filter": "(uid={username})", "scope": "onelevel"}

        mock_res = []

        self.ldapobj.search_s.seed(user["base_dn"], ldap.SCOPE_ONELEVEL, user["search_filter"].format(username=username))(mock_res)
        result = _do_simple_bind('cn=manager,dc=example,dc=com', 'ldaptest', user_search=user, group_search=None, username=username, password=password)

        self.assertEquals(self.ldapobj.methods_called(), [
                'initialize',
                'simple_bind_s',
                'whoami_s',
                'search',
                'result',
                'unbind'
            ]
        )
        self.assertFalse(result)


    def test_search_invalid_password(self):
        username = 'sarah_connor'
        password = 'bad_password'
        user = {"base_dn": "ou=users,dc=example,dc=com", "search_filter": "(uid={username})", "scope": "onelevel"}

        mock_res_id = 1234
        mock_res = (ldap.RES_SEARCH_RESULT, None)

        self.ldapobj._search.seed(user["base_dn"], ldap.SCOPE_ONELEVEL, user["search_filter"].format(username=username))(mock_res_id)
        self.ldapobj._result.seed(mock_res_id, all=0)(mock_res)
        result = _do_simple_bind('cn=manager,dc=example,dc=com', 'ldaptest', user_search=user, group_search=None, username=username, password=password)

        self.assertEquals(self.ldapobj.methods_called(), [
                'initialize',
                'simple_bind_s',
                'whoami_s',
                'search',
                'result',
                'unbind'
            ]
        )
        self.assertFalse(result)


    def test_search_valid_username_valid_group(self):
        username = 'john_connor'
        password = 'HastaLavista'
        user_dn = 'uid={},ou=users,dc=example,dc=com'.format(username)
        mock_user_res_id = 1234
        mock_user_res = (ldap.RES_SEARCH_RESULT, [(user_dn, LDAPAuthenticationBackendTestCase.directory[user_dn])])

        groupname = 'resistance'
        group_dn = 'cn={groupname},ou=groups,dc=example,dc=com'.format(groupname=groupname)
        mock_group_res_id = 9999
        mock_group_res = (ldap.RES_SEARCH_RESULT, [(group_dn, LDAPAuthenticationBackendTestCase.directory[group_dn])])

        user = {"base_dn": "ou=users,dc=example,dc=com", "search_filter": "(uid={username})", "scope": "onelevel"}
        group = {"base_dn": "ou=groups,dc=example,dc=com", "search_filter": "(&(cn=%s)(memberUid={username}))"%groupname, "scope": "subtree"}

        self.ldapobj._search.seed(user["base_dn"], ldap.SCOPE_ONELEVEL, user["search_filter"].format(username=username))(mock_user_res_id)
        self.ldapobj._search.seed(group["base_dn"], ldap.SCOPE_SUBTREE, group["search_filter"].format(username=username))(mock_group_res_id)
        self.ldapobj._result.seed(mock_user_res_id, all=0)(mock_user_res)
        self.ldapobj._result.seed(mock_group_res_id, all=0)(mock_group_res)

        result = _do_simple_bind('cn=manager,dc=example,dc=com', 'ldaptest', user_search=user, group_search=group, username=username, password=password)

        self.assertEquals(self.ldapobj.methods_called(), [
                'initialize',
                'simple_bind_s',
                'whoami_s',
                'search',
                'result',
                'result',
                'initialize',
                'simple_bind_s',
                'whoami_s',
                'unbind',
                'search',
                'result',
                'result',
                'unbind'
            ]
        )
        self.assertTrue(result)


    def test_search_valid_username_invalid_group(self):
        username = 'john_connor'
        password = 'HastaLavista'
        user_dn = 'uid={},ou=users,dc=example,dc=com'.format(username)
        mock_user_res_id = 1234
        mock_user_res = (ldap.RES_SEARCH_RESULT, [(user_dn, LDAPAuthenticationBackendTestCase.directory[user_dn])])

        groupname = 'invalid_group'
        group_dn = 'cn={groupname},ou=groups,dc=example,dc=com'.format(groupname=groupname)
        mock_group_res_id = 9999
        mock_group_res = (ldap.RES_SEARCH_RESULT, None)

        user = {"base_dn": "ou=users,dc=example,dc=com", "search_filter": "(uid={username})", "scope": "onelevel"}
        group = {"base_dn": "ou=groups,dc=example,dc=com", "search_filter": "(&(cn=%s)(memberUid={username}))"%groupname, "scope": "subtree"}

        self.ldapobj._search.seed(user["base_dn"], ldap.SCOPE_ONELEVEL, user["search_filter"].format(username=username))(mock_user_res_id)
        self.ldapobj._search.seed(group["base_dn"], ldap.SCOPE_SUBTREE, group["search_filter"].format(username=username))(mock_group_res_id)
        self.ldapobj._result.seed(mock_user_res_id, all=0)(mock_user_res)
        self.ldapobj._result.seed(mock_group_res_id, all=0)(mock_group_res)

        result = _do_simple_bind('cn=manager,dc=example,dc=com', 'ldaptest', user_search=user, group_search=group, username=username, password=password)

        self.assertEquals(self.ldapobj.methods_called(), [
                'initialize',
                'simple_bind_s',
                'whoami_s',
                'search',
                'result',
                'result',
                'initialize',
                'simple_bind_s',
                'whoami_s',
                'unbind',
                'search',
                'result',
                'unbind'
            ]
        )
        self.assertFalse(result)

    def test_search_with_reference_result(self):
        # This is for returning the referral object at calling 'result' method of LDAPObject
        self.mock_referral = [
            (None, ['ldap://fakeldap2.example.com/ou=cyberdyne,dc=example,dc=com']),
        ]

        user = {
            "base_dn": "ou=users,dc=example,dc=com",
            "search_filter": "(uid={username})",
            "scope": "subtree",
        }

        # This is a case that maximum referral hop will be exceeded
        result = _do_simple_bind('', '',
                                 user_search=user, group_search=None,
                                 username='john_connor', password='HastaLavista',
                                 ref_hop_limit=1)

        self.assertEquals(self.ldapobj.methods_called(),[
                'initialize',
                'simple_bind_s',
                'whoami_s',
                'search',
                'result',
                'result',
                'result',
                'whoami_s',
                'unbind'
            ]
        )
        self.assertTrue(result)
        self.assertEqual(len(self.log_handler.messages['warning']), 0)

    def test_search_with_reference_result_but_exceeded_maximum_referal_hop(self):
        # This is for returning the referral object at calling 'result' method of LDAPObject
        self.mock_referral = [
            (None, ['ldap://fakeldap2.example.com/ou=cyberdyne,dc=example,dc=com']),
        ]

        user = {
            "base_dn": "ou=users,dc=example,dc=com",
            "search_filter": "(uid={username})",
            "scope": "subtree",
        }

        result = _do_simple_bind('', '',
                                 user_search=user, group_search=None,
                                 username='john_connor', password='HastaLavista',
                                 ref_hop_limit=0)

        self.assertEquals(self.ldapobj.methods_called(),[
                'initialize',
                'simple_bind_s',
                'whoami_s',
                'search',
                'result',
                'result',
                'result',
                'whoami_s',
                'unbind'
            ]
        )
        self.assertTrue(result)
        self.assertTrue(len(self.log_handler.messages['warning']) > 0)
        self.assertTrue(re.match(r'^Referral hop limit is exceeded',
                                 self.log_handler.messages['warning'][0]))

def _do_simple_bind(bind_dn, bind_pw, uri=DEFAULT_URI, user_search=None, group_search=None, username=None, password=None, ref_hop_limit=0):
    backend = LDAPAuthenticationBackend(uri, use_tls=False, bind_dn=bind_dn, bind_pw=bind_pw, user=user_search, group=group_search, ref_hop_limit=ref_hop_limit)
    return backend.authenticate(username, password)


if __name__ == '__main__':
    sys.exit(unittest2.main())
