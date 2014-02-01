import struct 

class DecoderError(Exception):
    pass

def unpack_varint(data, length):
    """ Decodes a variable length integer """
    if length == 1: 
        data = struct.unpack('!h', '\x00' + data)[0]
    elif length == 2:
        data = struct.unpack('!h', data)[0]
    elif length == 4:
        data = struct.unpack('!i', data)[0]
    else:
        data = -1
    return data

def encoder(data, tagmap):
    keys = tagmap.keys()
    keys.sort()
    packed_data = ''

    for key in keys:
        try:
            attr = data[tagmap[key][0]]
        except KeyError:
            continue

        tag = key[0] + key[1] + key[2]
        tag = struct.pack('!B', tag)
        package = attr.pack()
        if len(package) < 128:
            length = struct.pack('!B', len(package))
        else:  # HACK.. this will only support lengths up to 254.
            length = struct.pack('!BB', 129, len(package))
        packed_data += tag + length + package
        #print repr(tag + length + package)

    return packed_data

def decoder(data, tagmap, ignore_errors=True, decode_as_list=False):
    """ Decodes binary data encoded in a BER format and return a dictonary.

    Keyword Arguments:
    data -- the binary data to decode stored in a string
    tagmap -- a dictionary keyed by a tag tuple (class, format, id) as integer
              values with tuple values (name, type).
    ignore_errors -- will cause the decoder to skip past errors and continue

    """
    if decode_as_list:
        results = list()
    else:
        results = dict()

    while len(data) > 0:
        chunk = 1
        tag = ord(data[:chunk])
        data = data[chunk:]
        tag_class = tag & 0xC0
        tag_format = tag & 0x20
        tag_id = tag & 0x1F

        length = ord(data[:chunk])
        data = data[chunk:]
        if length & 0x80 == 0x80: # length field is longer than a byte
            n = length & 0x7F 
            length = unpack_varint(data[:n], n)
            data = data[n:] 
        try:
            name = tagmap[(tag_class, tag_format, tag_id)][0]
            inst = tagmap[(tag_class, tag_format, tag_id)][1]
            val = inst(data[:length], length) # exception handling?
            val.tag = (tag_class, tag_format, tag_id)
        except KeyError:
            if ignore_errors:
                print 'Unfound tag %s,%s,%s' % (tag_class, tag_format, tag_id)
                continue
            else:
                raise DecoderError("Tag not found in tagmap")
        finally:
            data = data[length:] 
   
        if decode_as_list:
            results.append(val)
        else:
            results[name] = val

    return results
