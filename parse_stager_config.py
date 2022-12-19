#!/usr/bin/env python3
'''
By Daniel Mayer (Daniel@Stairwell.com), @dan__mayer
'''

import argparse
import json
import os
import struct
import sys

from resources import *

class StagerConfig:
    def __init__(self, f):
        '''
        f: file path
        '''
        self.data = None
        self.config = {}

        try:
            fobj = open(f, 'rb')
        except Exception as e:
            sys.stderr.write(f'error opening file {f}: {e}')
            sys.exit(1)

        with fobj:
            self.data = fobj.read()
            self._parse_config()

    def _clean(self, s, data_type):
        '''
        s: bytestring to clean
        data_type: string determining which cleaning method is appropriate

        Converts the bytes of the various stager fields into human-readable settings
        '''
        result = None
        if data_type == 'string':
           result = s.split(b"\x00")[0].decode('utf-8')
        elif data_type == 'headers':
            headers = self._clean(s, 'string')
            lines = headers.split("\r\n")[:-1]
            result = {k: v for k, v in (line.split(": ") for line in lines)}
        elif data_type == 'port':
            result = struct.unpack('<I', s)[0]
        elif data_type == 'watermark':
            result = struct.unpack('>I', s)[0]
        elif data_type == 'inet_flags':
            n = struct.unpack('<I',s)[0]
            constants = []
            for flag, value in INET_CONSTANTS.items():
                if n & value == value:
                    constants.append(flag)
            result = constants
        else:
            raise Exception(f'Unknown type {data_type} passed to _clean()')

        return result

    def _parse_config(self):
        '''
        Attempts to parse stager config data from a bytes-like object.
        The three types of stagers' (HTTP, SMB, DNS) templates
        can be found in resources.py
        '''
        for i, pattern in enumerate([HTTP_TEMPLATE, DNS_TEMPLATE, SMB_TEMPLATE]):
            match = pattern.search(self.data)
            if match:
                # order results correctly and filter out None values
                gd = match.groupdict()
                order = ['netloc', 'path', 'pipe_name', 'port', 'headers',
                         'inet_flags', 'watermark']
                filtered = {k: gd[k] for k in order if gd.get(k) is not None}
                # clean each field appropiately
                operations = {
                    'netloc': lambda x: self._clean(x, 'string'),
                    'path': lambda x: self._clean(x, 'string'),
                    'pipe_name': lambda x: self._clean(x, 'string'),
                    'port': lambda x: self._clean(x, 'port'),
                    'headers': lambda x : self._clean(x, 'headers'),
                    'inet_flags': lambda x: self._clean(x, 'inet_flags'),
                    'watermark': lambda x: self._clean(x, 'watermark'),
                }
                # set the settings to contain the cleaned data
                for k,v in filtered.items():
                    self.config[k] = operations[k](v)
                # logic for determining type
                self.config['type'] = ['HTTP', 'DNS', 'SMB'][i]
                if self.config['type'] == 'HTTP':
                    if 'INTERNET_FLAG_SECURE' in self.config['inet_flags']:
                        self.config['type'] = 'HTTPS'

    def get_config(self):
        '''Returns the settings as a JSON object, or None if none exist'''
        return json.dumps(self.config, indent=4) if self.config else None


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Parses CobaltStrike Stager Shellcode.')
    parser.add_argument('file', help='File path to stager shellcode')
    args = parser.parse_args()

    if os.path.isfile(args.file):
        result = StagerConfig(args.file).get_config()
        if result:
            print(result)
        else:
            print(f'[-] Stager Configuration not found in file {args.file}')
    else:
        print(f'[-] No file found at the path {args.file}')
