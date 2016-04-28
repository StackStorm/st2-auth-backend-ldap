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

import logging

import ldap

__all__ = [
    'LDAPAuthenticationBackend'
]

LOG = logging.getLogger(__name__)


class LDAPAuthenticationBackend(object):
    """
    Backend which reads authentication information from a ldap server.
    The backend tries to bind the ldap user with given username and password.
    If the bind was successful, it tries to find the user in the given group.
    If the user is in the group, he will be authenticated.
    """

    def __init__(self, ldap_server, domain, use_tls):
        """
        :param ldap_server: URL of the LDAP Server
        :type ldap_server: ``str``
        :param domain: User email domain
        :type domain: ``str``
        :param use_tls: Boolean parameter to set if tls is required
        :type use_tls: ``bool``
        """
        self._ldap_server = ldap_server
        self._domain = domain
        if use_tls != "True" or "ldaps" in ldap_server:
            self._use_tls = False
        else:
            self._use_tls = True

    def authenticate(self, username, password):
        try:
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            connect = ldap.initialize(self._ldap_server)
            connect.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
            if self._use_tls:
                connect.set_option(ldap.OPT_X_TLS, ldap.OPT_X_TLS_DEMAND)
                connect.start_tls_s()
                LOG.debug('using TLS')
            try:
                connect.simple_bind_s('{0}@{1}'.format(username, self._domain), password)
                LOG.debug('Authentication for user "{}" successful'.format(username))
                return True
            except ldap.LDAPError as e:
                LOG.debug('Authentication for user "{0}" failed. \
                    LDAP Error: {1}'.format(username, str(e)))
                return False
            finally:
                connect.unbind()
        except ldap.LDAPError as e:
            LOG.debug('Authentication for user "{0}" failed. \
                LDAP Error: {1}'.format(username, str(e)))
            return False

    def get_user(self, username):
        pass
