# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

# pylint: disable=no-member

from __future__ import absolute_import
import re
import ldap
import logging
LOG = logging.getLogger(__name__)

__all__ = [
    'LDAPAuthenticationBackend'
]


class LDAPAuthenticationBackend(object):
    """
    Backend which reads authentication information from a ldap server.
    Supported authentication methods:
        * Anonymous session with user lookup.
        * Bind Distinguish Name with user lookup.
        * Bind Distinguish Name with user and group lookup.
    """
    def __init__(self, ldap_uri, use_tls=False, bind_dn='', bind_pw='', user=None, group=None):
        """
        :param ldap_uri: URL of the LDAP Server. <proto>://<host>[:port]
        :type ldap_uri:  ``str``
        :param use_tls:  Boolean parameter to set if tls is required.
        :type use_tls:   ``bool``
        :param bind_dn:  The Distinguish Name account to bind to the ldap server.
        :type bind_dn:   ``str``
        :param bind_pw:  The Distinguish Name account's password.
        :type bind_pw:   ``str``
        :param user:     Search parameters used to authenticate the user.
                         (base_dn, search_filter, scope)
        :type user:      ``dict``
        :param group:    Search parameters used to confirm the user is a member of a given group.
                         (base_dn, search_filter, scope)
        :type group:     ``dict``
        """
        self._ldap_uri = ldap_uri
        self._use_tls = use_tls
        self._bind_dn = bind_dn
        self._bind_pw = bind_pw
        self._user = user
        self._group = group

    def _scope_to_ldap_option(self, scope):
        """
        Transform scope string into ldap module constant.
        """
        if 'base' in scope.lower():
            opt = ldap.SCOPE_BASE
        elif 'onelevel' in scope.lower():
            opt = ldap.SCOPE_ONELEVEL
        else:
            opt = ldap.SCOPE_SUBTREE
        return opt

    def authenticate(self, username, password):
        """
        Simple binding to authenticate username/password against the LDAP server.
        :param username: username to authenticate.
        :type username: ``str``
        :param password: password to use with for authentication.
        :type password: ``str``
        """
        connection = self._ldap_connect()
        if not connection:
            return False
        try:
            if self._bind_dn == '' == self._bind_pw:
                LOG.debug('Attempting to fast bind anonymously.')
                connection.simple_bind_s()
                LOG.debug('Connected to LDAP as %s ' % connection.whoami_s())
            else:
                LOG.debug('Attempting to fast bind with DN.')
                if self._bind_dn.find('{username}') != -1:
                    self._bind_dn = self._bind_dn.format(username=username)
                if self._bind_pw.find('{password}') != -1:
                    self._bind_pw = self._bind_pw.format(password=password)

                connection.simple_bind_s(self._bind_dn, self._bind_pw)
                LOG.debug('Connected to LDAP as %s ' % connection.whoami_s())

            if self._user:
                # Authenticate username and password.
                result = self._ldap_search(connection, username, self._user)
                if len(result) != 1:
                    LOG.debug('Failed to uniquely identify the user.')
                    return False
                user_dn = result[0][0]
                LOG.debug('DN identified as : %s' % user_dn)
                try:
                    user_connection = self._ldap_connect()
                    user_connection.simple_bind_s(user_dn, password)
                    LOG.debug('User successfully authenticated as %s ' % connection.whoami_s())
                except ldap.LDAPError as e:
                    LOG.debug('LDAP Error: %s' % (str(e)))
                    return False
                finally:
                    user_connection.unbind()

            if self._group:
                # Confirm the user is a member of a given group.
                result = self._ldap_search(connection, username, self._group)
                if len(result) != 1:
                    LOG.debug('Unable to find %s in the group.' % username)
                    return False

        except ldap.LDAPError as e:
            LOG.debug('(authenticate) LDAP Error: %s : Type %s' % (str(e), type(e)))
            return False
        finally:
            connection.unbind()
            LOG.debug('LDAP connection closed')
        return True

    def _ldap_connect(self):
        """
        Prepare ldap object for binding phase.
        """
        try:
            # set ldap options before connecting LDAP server
            ldap.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
            ldap.set_option(ldap.OPT_REFERRALS, ldap.OPT_OFF)

            connection = ldap.initialize(self._ldap_uri)
            if self._use_tls:
                # Require TLS connection.
                ldap.set_option(ldap.OPT_X_TLS, ldap.OPT_X_TLS_DEMAND)
                # Require server certificate but ignore it's validity. (allow self-signed)
                ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
                connection.start_tls_s()
                LOG.debug('Connection now using TLS')
            return connection
        except ldap.LDAPError as e:
            LOG.debug('(_ldap_connect) LDAP Error: %s : Type %s' % (str(e), type(e)))
            return False

    def _ldap_search(self, connection, username, criteria):
        """
        Perform a search against the LDAP server using an established connection.
        :param connection: The established LDAP connection.
        :type connection: ``LDAPobject``
        :param username: The username to be used in the search filter.
        :type username: ``str``
        :param criteria: A dictionary of search filter parameters.
                         (base_dn, search_filter, scope, pattern)
        :type criteria: ``dict``
        """
        results = []
        base_dn = criteria['base_dn']
        search_filter = criteria['search_filter'].format(username=username)
        scope = self._scope_to_ldap_option(criteria['scope'])

        LOG.debug('Searching ... %s %s %s' % (base_dn, scope, search_filter))

        result_id = connection.search(base_dn, scope, search_filter)
        while 1:
            r_type, r_data = connection.result(result_id, all=0)

            if r_type == ldap.RES_SEARCH_RESULT:
                break
            elif r_type == ldap.RES_SEARCH_ENTRY:
                results.append(r_data[0])
            elif r_type == ldap.RES_SEARCH_REFERENCE:
                # extract referral informations (uri and bind_dn)
                referral_ptrn = re.compile("^(.*/)(.*)$")
                referral_info = referral_ptrn.match(r_data[0][1][0])

                if referral_info and len(referral_info.groups()) == 2:
                    # update connection informations to referral's one
                    self._ldap_uri = referral_info.group(1)
                    criteria['base_dn'] = referral_info.group(2)

                    # re-connect referred LDAP server
                    referral_conn = self._ldap_connect()
                    if referral_conn:
                        try:
                            if self._bind_dn == '' == self._bind_pw:
                                referral_conn.simple_bind_s()
                            else:
                                referral_conn.simple_bind_s(self._bind_dn, self._bind_pw)

                            # dereference referral objects
                            results.extend(self._ldap_search(referral_conn, username, criteria))
                        except ldap.LDAPError as e:
                            LOG.debug('LDAP Error: %s' % (str(e)))
                        finally:
                            referral_conn.unbind()
            else:
                LOG.warning("Unknown type('%s') is appear" % r_type)

        # Disabled to prevent logging sensitive data.
        # LOG.debug("RESULT: {}".format(result))
        return results

    def get_user(self, username):
        pass
