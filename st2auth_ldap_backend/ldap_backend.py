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
    def __init__(self, ldap_uri, use_tls=False, bind_dn='', bind_pw='', user=None, group=None,
                 ref_hop_limit=0):
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
        :param ref_hop_limit:   Maximum referral hop numbers (0 means never search referral objects)
        :type ref_hop_limit:    ``int``
        """
        self._ldap_uri = ldap_uri
        self._use_tls = use_tls
        self._bind_dn = bind_dn
        self._bind_pw = bind_pw
        self._user = user
        self._group = group
        self._ref_hop_limit = ref_hop_limit

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

    def _get_ldap_search_results(self, connection, username, criteria, result_id, current_ref_hop):
        """
        The '_get_ldap_search_results()' returns the result of parsing a LDAP tree.
        Internally, this calls 'result' method of the LDAPObject.
        That method returns a tuple which has following two parameters.

        * r_type: This value can be one of the following three values
          - RES_SEARCH_ENTRY      : describes that the 'r_type' has a LDAP entry
          - RES_SEARCH_REFERENCE  : describes that the 'r_type' has a referral information
          - RES_SEARCH_RESULT     : describes the end of this search
        * r_data: A contents of search response

        There is a similar metho to parse LDAP tree that is 'search()'.
        But that method can't get the type information which is described 'r_type' in here.
        Therefore, this method parses LDAP tree by calling 'result()' method recursively.
        """
        results = []
        r_type, r_data = connection.result(result_id, all=0)

        if r_type == ldap.RES_SEARCH_ENTRY:
            results.append(self._get_ldap_search_entry(r_data))

            _results = self._get_ldap_search_results(connection, username, criteria, result_id,
                                                     current_ref_hop)
            # This condition prevents to append empty results.
            if _results:
                results.append(_results)
        elif r_type == ldap.RES_SEARCH_REFERENCE:
            _results = self._get_ldap_search_referral(r_data, username, criteria, current_ref_hop)
            if _results:
                results.append(_results)

            _results = self._get_ldap_search_results(connection, username, criteria, result_id,
                                                     current_ref_hop)
            if _results:
                results.append(_results)

        return results

    def _get_ldap_search_entry(self, response_data):
        return response_data[0]

    def _get_ldap_search_referral(self, response_data, username, criteria, current_ref_hop):
        # extract referral informations (uri and bind_dn)
        referral_ptrn = re.compile("^(.*/)(.*)$")
        referral_info = referral_ptrn.match(response_data[0][1][0])

        _criteria = criteria.copy()

        results = []
        if referral_info and len(referral_info.groups()) == 2:
            # update connection informations to referral's one
            self._ldap_uri = referral_info.group(1)
            _criteria['base_dn'] = referral_info.group(2)

            # re-connect referred LDAP server
            referral_conn = self._ldap_connect()

            if referral_conn:
                try:
                    if self._bind_dn == '' == self._bind_pw:
                        referral_conn.simple_bind_s()
                    else:
                        referral_conn.simple_bind_s(self._bind_dn, self._bind_pw)

                    # dereference referral objects
                    results = self._ldap_search(referral_conn, username, _criteria,
                                                current_ref_hop + 1)
                except ldap.LDAPError as e:
                    LOG.debug('LDAP Error: %s' % (str(e)))
                finally:
                    referral_conn.unbind()

        return results

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

    def _ldap_search(self, connection, username, criteria, current_ref_hop=0):
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
        # checks referral search hop limit
        if current_ref_hop > int(self._ref_hop_limit):
            LOG.warning('Referral hop limit is exceeded (current_ref_hop: %d)' % current_ref_hop)
            return []

        base_dn = criteria['base_dn']
        search_filter = criteria['search_filter'].format(username=username)
        scope = self._scope_to_ldap_option(criteria['scope'])

        LOG.debug('Searching ... %s %s %s' % (base_dn, scope, search_filter))

        result_id = connection.search(base_dn, scope, search_filter)

        return self._get_ldap_search_results(connection, username, criteria, result_id,
                                             current_ref_hop)

    def get_user(self, username):
        pass
