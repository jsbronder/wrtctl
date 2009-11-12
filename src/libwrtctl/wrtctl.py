"""
File: wrtctl.py

Description: python wrapper class for _wrtctl C class.

Copyright 2009, Brontes Technologies Inc.

Current Author(s): Phil Lamoreaux
"""

import _wrtctl


class wrtctl(object):
    """Python class-style wrapper for _wrtctl C functionality."""

    def __init__(self, enable_log=True, verbose=False):
        self.defaultParam = _wrtctl.get_param_defaults()
        self.wrtctlObject = _wrtctl.alloc_client(enable_log, verbose)
        self.ctxObject = None

    def __getOrSetDefault(param, defaultKey):
        if param is None:
            param = self.defaultParam[defaultKey]
        else:
            self.defaultParam[defaultKey] = param

    def start_stunnel_client(self, hostname, key_path=None, port=None, wrtctlPort=None, wrtctldPort=None):
        self.__getOrSetDefault(hostname   , 'HOSTNAME')
        self.__getOrSetDefault(key_path   , 'DEFAULT_KEY_PATH')
        self.__getOrSetDefault(port       , 'WRTCTLD_DEFAULT_PORT')
        self.__getOrSetDefault(wrtctlPort , 'WRTCTL_SSL_PORT')
        self.__getOrSetDefault(wrtctldPort, 'WRTCTLD_SSL_PORT')
        self.ctxObject = _wrtctl.start_stunnel_client(hostname, key_path, port, wrtctlPort, wrtctldPort)

    def create_connection(self, hostname=None, port=None):
        self.__getOrSetDefault(hostname   , 'HOSTNAME')
        self.__getOrSetDefault(port       , 'WRTCTLD_DEFAULT_PORT')
        _wrtctl.create_connection(self.wrtctlObject, hostname, port)

    def queue_net_command(self, ID, subsystemStr, valueStr=''):
        _wrtctl.queue_net_command(self.wrtctlObject, ID, subsystemStr, valueStr)

    def wait_on_response(self, timeoutSec=0, flushSendQueue=True):
        """Return 0=got response, 1=timeout, -n=error."""
        rv = _wrtctl.wait_on_response(self.wrtctlObject, timeoutSec, flushSendQueue)
        if rv == self.defaultParam['NET_OK']:
            return 0
        elif rv == self.defaultParam['NET_ERR_TIMEOUT']:
            return 1;
        if rv > 0:
            return -rv
        return rv

    def get_net_response(self):
        """Get and return (ID, subsystemStr, valueStr)."""
        return _wrtctl.get_net_response(self.wrtctlObject)

    def __del__(self):
        if self.ctxObject:
            pass
##            ?deallocate_stunnel(self.ctxObject)
