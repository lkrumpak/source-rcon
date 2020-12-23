import socket
import struct


class RCONError(Exception):
    """Base Exception for RCON."""


class RCONAuthenticationError(RCONError):
    """Raised for failed Authentication."""


class RCONPacket:
    def __init__(self, id_=0, type_=-1, body_=''):
        self.id = id_
        self.type = type_
        self.body = body_

    def __str__(self):
        return self.body

    def size(self):
        return len(self.body) + 10

    def pack(self):
        terminated_body = self.body.encode() + b"\x00\x00"
        size = struct.calcsize("<ii") + len(terminated_body)
        return struct.pack("<iii", size, self.id, self.type) + terminated_body


class RCONConnection:
    def __init__(self, host, port=27015, password=''):
        self.server = host
        self.port = port
        self._connect(host, port)
        self._authenticate(password)

    def _connect(self, host, port):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        self._sock.connect((host, port))

    def _authenticate(self, password):
        auth_pkt = RCONPacket(1, 3, password)
        self._send_pkt(auth_pkt)
        auth_response = self._recv_pkt()
        if auth_response.type == 0:
            auth_response = self._recv_pkt()
        if auth_response.type != 2:
            raise RCONError('Received invalid auth response packet')
        if auth_response.id == -1:
            raise RCONAuthenticationError('Bad password')

    def exec_command(self, command):
        cmd_pkt = RCONPacket(1, 2, command)
        self._send_pkt(cmd_pkt)
        resp = self._recv_pkt()
        return resp.body

    def _send_pkt(self, pkt):
        data = pkt.pack()
        self._sock.sendall(data)

    def _recv_pkt(self):
        while True:
            header = self._sock.recv(struct.calcsize('<3i'))
            if len(header) != 0:
                break

        (pkt_size, pkt_id, pkt_type) = struct.unpack('<3i', header)
        body = self._sock.recv(pkt_size - 8)
        return RCONPacket(pkt_id, pkt_type, body.decode())


