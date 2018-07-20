#!/usr/bin/env python
# MSF-RPC - A  Python library to facilitate MSG-RPC communication with Metasploit
# Ryan Linn  - RLinn@trustwave.com
# Copyright (C) 2011 Trustwave
# This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with this program. If not, see <http://www.gnu.org/licenses/>.

import msgpack
import http.client as httplib  # python3的httplib为http.client


class Msfrpc:
    class MsfError(Exception):
        def __init__(self, msg):
            self.msg = msg

        def __str__(self):
            return repr(self.msg)

    class MsfAuthError(MsfError):
        def __init__(self, msg):
            self.msg = msg

    def __init__(self, opts=[]):
        self.host = opts.get('host') or "127.0.0.1"
        self.port = opts.get('port') or 55553
        self.uri = opts.get('uri') or "/api/"
        self.ssl = opts.get('ssl') or False
        self.authenticated = False
        self.token = False
        self.headers = {"Content-type": "binary/message-pack"}
        if self.ssl:
            self.client = httplib.HTTPSConnection(self.host, self.port)
        else:
            self.client = httplib.HTTPConnection(self.host, self.port)

    def encode(self, data):
        return msgpack.packb(data, use_bin_type=True)

    def decode(self, data):
        result = msgpack.unpackb(data, raw=False)
        result = self.convert(result)
        return result

    def call(self, meth, opts=[]):
        if meth != "auth.login":
            if not self.authenticated:
                raise self.MsfAuthError("MsfRPC: Not Authenticated")

        if meth != "auth.login":
            opts.insert(0, self.token)

        opts.insert(0, meth)
        params = self.encode(opts)
        self.client.request("POST", self.uri, params, self.headers)
        resp = self.client.getresponse()
        return self.decode(resp.read())

    def login(self, user, password):
        ret = self.call('auth.login', [user, password])
        ret = self.convert(ret)
        if ret.get('result') == 'success':
            self.authenticated = True
            self.token = ret.get('token')
            return True
        else:
            raise self.MsfAuthError("MsfRPC: Authentication failed")
    
    def convert(self, data):
        """convert dict from bytes to str"""
        if isinstance(data, bytes):  
            return data.decode('utf-8')
        if isinstance(data, dict):   
            return dict(map(self.convert, data.items()))
        if isinstance(data, tuple):  
            return map(self.convert, data)
        return data


if __name__ == '__main__':

    # Create a new instance of the Msfrpc client with the default options
    client = Msfrpc({'host': '192.168.9.225', 'port': 55553})

    # Login to the msfmsg server using the password "abc123"
    resp = client.login('root', 'password')

    # Get a list of the exploits from the server
    mod = client.call('module.exploits')
    # print(mod)
    # Grab the first item from the modules value of the returned dict
    print("Compatible payloads for : %s\n" % mod['modules'][0])

    # Get the list of compatible payloads for the first option
    ret = client.call('module.compatible_payloads', [mod['modules'][0]])
    # print(ret)
    for i in (ret.get('payloads')):
        print("\t%s" % i)
