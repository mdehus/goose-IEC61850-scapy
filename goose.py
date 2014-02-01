import struct
import binascii

from scapy.all import *

import BER

class ASNType(object):
    tag = ''
    def __init__(self, data='', length=0):
        pass

    def unpack(self, data):
        raise NotImplemented()

    def pack(self, data):
        raise NotImplemented()

    def __str__(self):
        return str(self.data)

    def __repr__(self):
        return str(self.data)

class Integer(ASNType):
    def __init__(self, data='', length=0):
        self.data = BER.unpack_varint(data, length)

    def pack(self):
        if isinstance(self.data, int):
            if self.data <= 255:
                return struct.pack('!B', self.data)
            elif self.data <= 65535:
                return struct.pack('!h', self.data)
            else:
                return struct.pack('!i', self.data)
        if isinstance(self.data, long):
            return struct.pack('!l', self.data)

class VisibleString(ASNType):
    def __init__(self, data='', length=0):
        self.data = data

    def __repr__(self):
        return "'" + self.data + "'"

    def pack(self):
        return self.data

class Boolean(ASNType):
    ID = 3
    def __init__(self, data='', length=0):
        self.data = struct.unpack('!b', data)[0]

    def __repr__(self):
        if self.data:
            return "True"
        else:
            return "False"

    def pack(self):
        return struct.pack('!b', self.data)

class UTCTime(ASNType):
    def __init__(self, data='', length=0):
        self.data = struct.unpack('!d', data)[0]

    def pack(self):
        return struct.pack('!d', self.data)

class UnsignedInteger(ASNType):
    def __init__(self, data='', length=0):
        self.data = struct.unpack()

class Float(ASNType):
    def __init__(self, data='', length=0):
        self.data = struct.unpack('!f', data)[0]

    def pack(self):
        return struct.data('!f', data) 

class Real(Float):
    pass

class OctetString(ASNType):
    def __init__(self, data='', length=0):
        self.data = struct.unpack('!d', data)[0]

class BitString(ASNType):
    ID = 4
    def __init__(self, data='', length=0):
        c = {'0': '0000', '1': '0001', '2': '0010', 
             '3':'0011', '4':'0100', '5':'0101', 
             '6':'0110', '7':'0111', '8':'1000', 
             '9':'1001', 'a':'1010', 'b':'1011', 
             'c':'1100', 'd':'1101', 'e':'1110', 
             'f':'1111'}
        self.padding = struct.unpack('!h', '\x00'+data[:1])[0]
        h = binascii.b2a_hex(data[1:])
        self.data = ''
        for i in h:
            self.data += c[i]

    def pack(self):
        packed_padding = struct.pack('!B', self.padding)
        packed_data = struct.pack('!h', int(self.data, 2))
        return packed_padding + packed_data

class ObjectID(ASNType):
    pass

class BCD(ASNType):
    pass

class BooleanArray(ASNType):
    pass

class UTF8String(ASNType):
    pass
    
class Data(object):
    tag = ''
    tagmap = {(128,0,3):('boolean', Boolean), 
              (128,0,4):('bitstring', BitString),
              (128,0,5):('integer', Integer), 
              (129,0,6):('unsigned', UnsignedInteger),
              (128,0,7):('float', Float), 
              (128,0,8):('real', Real),
              (128,0,9):('octetstring', OctetString),
              (129,0,10):('visiblestring', VisibleString),
              (128,0,12):('binarytime', UTCTime), 
              (128,0,13):('bcd', BCD),
              (129,0,14):('booleanarray', BooleanArray),
              (128,0,15):('objID', ObjectID),
              (128,0,16):('mMSString', UTF8String), 
              (128,0,17):('utcstring', UTCTime)}

    def __init__(self, data=None, length=0):
        self.tagmap[(128,32,1)] = ('array', Data)
        self.tagmap[(128,32,2)] = ('structure', Data)
        self.data = BER.decoder(data, self.tagmap, decode_as_list=True)

    def __getitem__(self, index):
        return self.data[index]

    def __repr__(self):
        return repr(self.data)

    def pack(self):
        """ This is a hack, and should probably be integrated in to
            the BER encoder at some point.
        """
        packed_data = ''
        for i in self.data:
            tag = i.tag[0] + i.tag[1] + i.tag[2]
            tag = struct.pack('!B', tag)
            package = i.pack()
            if len(package) < 128:
                length = struct.pack('!B', len(package))
            else: # HACK.. this will only support lengths up to 254.
                length = struct.pack('!BB', 129, len(package))
            packed_data += tag + length + package

        return packed_data

class GOOSEPDU(object):
    ID = 97
    tagmap = {(128,0,0):('gocbRef', VisibleString), 
              (128,0,1):('timeAllowedToLive', Integer), 
              (128,0,2):('datSet', VisibleString), 
              (128,0,3):('goID', VisibleString),
              (128,0,4):('t', UTCTime), 
              (128,0,5):('stNum', Integer),
              (128,0,6):('sqNum', Integer), 
              (128,0,7):('test',Boolean),
              (128,0,8):('confRev', Integer), 
              (128,0,9):('ndsCom', Boolean),
              (128,0,10):('numDataSetEntries', Integer),
              (128,32,11):('allData', Data)}

    def __init__(self, data=None, length=0):
        self.__dict__ = BER.decoder(data, self.tagmap)

    def pack(self):
        return BER.encoder(self.__dict__, self.tagmap)

class GOOSE(Packet):
    name = "GOOSE"
    fields_desc = [ ShortField("APPID", 3),
                    ShortField("Length", None),
                    ShortField("Reserved1", 0),
                    ShortField("Reserved2", 0),
                  ]
