#!/usr/bin/env python
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#
# uses code from cryptech_console
#
# Copyright (c) 2017, NORDUnet A/S All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
# - Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
#
# - Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in the
#   documentation and/or other materials provided with the distribution.
#
# - Neither the name of the NORDUnet nor the names of its contributors may
#   be used to endorse or promote products derived from this software
#   without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
# IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
# PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
# TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import os
import sys
import time
import struct
import atexit
import weakref
import logging
import argparse
import logging.handlers

import socket

import ssl

import tornado.gen

from tornado.tcpclient import TCPClient

from cryptech.console import FemtoTerm

class TCPIOStream(object):
    def __init__(self, connection):
        super(TCPIOStream, self).__init__()
        self.connection = connection
        self.read_chunk_size = self.connection.read_chunk_size

    def read_until(self, delimiter, callback=None, max_bytes=None):
        return self.connection.read_until(delimiter, callback, max_bytes)

    def read_bytes(self, num_bytes, callback=None, streaming_callback=None, partial=False):
        return self.connection.read_bytes(num_bytes, callback, streaming_callback, partial)

    def write(self, data, callback=None):
        return self.connection.write(data, callback)


class FemtoTermTLS(FemtoTerm):

    def __init__(self, host):
        self.host = host
        self.termios_setup()
        self.stdin_stream  = tornado.iostream.PipeIOStream(sys.stdin.fileno())
        self.stdout_stream = tornado.iostream.PipeIOStream(sys.stdout.fileno())
        self.closed = False

    @tornado.gen.coroutine
    def run(self):
        try:
            cty_tcp_client = yield TCPClient().connect(self.host, 8081, ssl_options = { 'cert_reqs': ssl.CERT_NONE})
            self.socket_stream = TCPIOStream(cty_tcp_client)
        except:
            sys.exit("Couldn't connect to socket {}".format(args.cty_socket))

        yield [self.stdout_loop(), self.stdin_loop()]

    @tornado.gen.coroutine
    def copy_loop_to_HSM(self, stream1, stream2, text1, text2, buffer_size = 1024):
        try:
            while not self.closed:
                buffer = yield stream1.read_bytes(buffer_size, partial = True)
                yield stream2.write(buffer.replace(text1, text2))
        except tornado.iostream.StreamClosedError:
            self.close()

    @tornado.gen.coroutine
    def copy_loop_from_HSM(self, stream1, stream2, text1, text2, buffer_size = 1024):
        try:
            while not self.closed:
                buffer = yield stream1.read_bytes(buffer_size, partial = True)
                yield stream2.write(buffer.replace(text1, text2))
        except tornado.iostream.StreamClosedError:
            self.close()

    def stdin_loop(self):
        return self.copy_loop_to_HSM(self.stdin_stream, self.socket_stream, b"\n", b"\r")

    def stdout_loop(self):
        return self.copy_loop_from_HSM(self.socket_stream, self.stdout_stream, b"\r\n", b"\n")


def main():
    tornado.ioloop.IOLoop.current().run_sync(FemtoTermTLS('10.1.10.9').run)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
