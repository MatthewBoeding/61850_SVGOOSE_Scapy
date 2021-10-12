from scapy.packet import Packet, bind_layers
from scapy.fields import XByteField, StrLenField, ShortField,Field
from scapy.layers.l2 import Ether, Dot1Q
from scapy.compat import raw, orb
import time, struct
from scapy.sendrecv import sendp

def getTimestamp():
    stamp = time.time_ns()
    frac = ((stamp/1000000000) - (stamp//1000000000))
    stamp = int(stamp//1000000000)
    t = struct.pack(">i", stamp)
    #Last 5 bits 11000
    bits = ''
    n = 0.5
    for i in range(0,24):
        if frac > n:
            bits += '1'
            frac = frac - n 
        else:
            bits += '0'
        n = n/2
    v = int(bits,2)
    timestamp = bytearray()
    while v:
        timestamp.append(v & 0xff)
        v >>= 8
    timestamp.append(0x18)
    t += timestamp
    return t

def vlenq2bytes(val):
    s = list()
    first = 0x80
    s.append(val & 0x7f)
    val = val >> 7
    count = 1
    while val:
        s.append(0x80 | (val & 0x7F))
        val = val >> 7
        count += 1
    if count > 1:
        s.append(first+count)
        s.reverse()
    return bytes(s)
        
def bytes2vlenq(m):
    count = l = 0
    i = 1
    longform = m[0] & 0x7f
    if m[0] > 127:
        count = longform
    else:
        l = longform
        i = 1
    for x in range(count):
        l = l << 7
        l = l + x
        i = i + 1
    return m[i:], l
        
class BERLenQField(Field):
    __slots__ = ["fld"]
    
    def __init__(self, name, default, fld):
        Field.__init__(self, name, default)
        self.fld = fld
        
    def i2m(self, pkt, x):
        if x is None:
            f = pkt.get_field(self.fld)
            try:
                x = f.i2len(pkt, pkt.getfieldval(self.fld))
            except:
                x = len(bytes([pkt.getfieldval(self.fld)]))
            x = vlenq2bytes(x)
            test = raw(x)
        return raw(x)
    
    def m2i(self, pkt, x):
        if x is None:
            return None, 0
        return bytes2vlenq(x)[1]
    
    def addfield(self, pkt, s, val):
        return s+self.i2m(pkt,val)
    
    def getfield(self, pkt, s):
        return bytes2vlenq(s)

class BERTotLenField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default)
        
    def i2m(self, pkt, x):
        if x is None:
            x = 0
        return raw(x)

    def m2i(self, pkt, x):
        if x is None:
            return None, 0
        return bytes2vlenq(x)[1]
    
    def addfield(self, pkt, s, val):
        return s+self.i2m(pkt,val)
    
    def getfield(self, pkt, s):
        return bytes2vlenq(s)


class GooseBoolean(Packet):
    name = "Boolean"
    fields_desc = [ XByteField("BooleanTag", 0x83),
                    BERLenQField("BooleanLength", None, "Data"),
                    StrLenField("Data", "", length_from=lambda x:x.BooleanLength)
                    ]
    def guess_payload_class(self, payload):
        if len(payload) > 0:
            data = orb(payload[0])
            return data_types[data]
        
    
class GooseBitString(Packet):
    name = "BitString"
    fields_desc = [ XByteField("BitStringTag", 0x84),
                    BERLenQField("BitStringLength", None, "Data"),
                    StrLenField("Data", "", length_from=lambda x:x.BitStringLength)
                    ]
    def guess_payload_class(self, payload):
        if len(payload) > 0:
            data = orb(payload[0])
            return data_types[data]
        
    
class GooseInteger(Packet):
    name = "Integer"
    fields_desc = [ XByteField("IntegerTag", 0x85),
                    BERLenQField("IntegerLength", None, "Data"),
                    StrLenField("Data", "", length_from=lambda x:x.IntegerLength)
                    ]
    def guess_payload_class(self, payload):
        if len(payload) > 0:
            data = orb(payload[0])
            return data_types[data]
        
    
class GooseUnsignedInteger(Packet):
    name = "Unsigned Integer"
    fields_desc = [ XByteField("UnsignedTag", 0x86),
                    BERLenQField("UnsignedLength", None, "Data"),
                    StrLenField("Data", "", length_from=lambda x:x.UnsignedLength)
                    ]
    
    def guess_payload_class(self, payload):
        if len(payload) > 0:
            data = orb(payload[0])
            return data_types[data]
        
class GooseFloat(Packet):
    name = "Float"
    fields_desc = [ XByteField("FloatTag", 0x87),
                    BERLenQField("FloatLength", None, "Data"),
                    StrLenField("Data", "", length_from=lambda x:x.gocbRef_Length)
                    ]
    def guess_payload_class(self, payload):
        if len(payload) > 0:
            data = orb(payload[0])
            return data_types[data]
        
class GooseReal(Packet):
    name = "Real"
    fields_desc = [ XByteField("RealTag", 0x88),
                    BERLenQField("RealLength", None, "Data"),
                    StrLenField("Data", "", length_from=lambda x:x.RealLength)
                    ]
    def guess_payload_class(self, payload):
        if len(payload) > 0:
            data = orb(payload[0])
            return data_types[data]

class GooseOctetString(Packet):
    name = "OctetString"
    fields_desc = [ XByteField("OctetStringTag", 0x89),
                    BERLenQField("OctetStringLength", None, "Data"),
                    StrLenField("Data", "", length_from=lambda x:x.OctetStringLength)
                    ]
    def guess_payload_class(self, payload):
        if len(payload) > 0:
            data = orb(payload[0])
            return data_types[data]
        
class GooseVisibleString(Packet):
    name = "VisibleString"
    fields_desc = [ XByteField("VisibleStringTag", 0x8A),
                    BERLenQField("VisibleStringLength", None, "Data"),
                    StrLenField("Data", "", length_from=lambda x:x.VisibleStringLength)
                    ]
    def guess_payload_class(self, payload):
        if len(payload) > 0:
            data = orb(payload[0])
            return data_types[data]
        
class GooseUTCTime(Packet):
    name = "UTCTime"
    fields_desc = [ XByteField("UTCTimeTag", 0x8C),
                    BERLenQField("UTCTimeLength", None, "Data"),
                    StrLenField("Data", "", length_from=lambda x:x.UTCTimeLength)
                    ]
    def guess_payload_class(self, payload):
        if len(payload) > 0:
            data = orb(payload[0])
            return data_types[data]
        
class GooseBCD(Packet):
    name = "BCD"
    fields_desc = [ XByteField("BCDTag", 0x8D),
                    BERLenQField("BCDLength", None, "Data"),
                    StrLenField("Data", "", length_from=lambda x:x.BCDLength)
                    ]
    def guess_payload_class(self, payload):
        if len(payload) > 0:
            data = orb(payload[0])
            return data_types[data]
        
class GooseBooleanArray(Packet):
    name = "BooleanArray"
    fields_desc = [ XByteField("BooleanArrayTag", 0x8E),
                    BERLenQField("BooleanArrayLength", None, "Data"),
                    StrLenField("Data", "", length_from=lambda x:x.BooleanArrayLength)
                    ]
      
class GooseObjectID(Packet):
    name = "ObjectID"
    fields_desc = [ XByteField("ObjectIDTag", 0x8F),
                    BERLenQField("ObjectIDLength", None, "Data"),
                    StrLenField("Data", "", length_from=lambda x:x.ObjectIDLength)
                    ]
    def guess_payload_class(self, payload):
        if len(payload) > 0:
            data = orb(payload[0])
            return data_types[data]
      
class GooseUTF8String(Packet):
    name = "UTF8String"
    fields_desc = [ XByteField("UTF8StringTag", 0x90),
                    BERLenQField("UTF8StringLength", None, "Data"),
                    StrLenField("Data", "", length_from=lambda x:x.UTF8StringLength)
                    ]
    def guess_payload_class(self, payload):
        if len(payload) > 0:
            data = orb(payload[0])
            return data_types[data]

data_types = {
    0x83: GooseBoolean,  
    0x84: GooseBitString, 
    0x85: GooseInteger,  
    0x86: GooseUnsignedInteger, 
    0x87: GooseFloat,  
    0x88: GooseReal, 
    0x89: GooseOctetString, 
    0x8A: GooseVisibleString, 
    0x8C: GooseUTCTime,  
    0x8D: GooseBCD, 
    0x8E: GooseBooleanArray, 
    0x8F: GooseObjectID, 
    0x90: GooseUTF8String,
    } 

class GOOSEDATA(Packet):
    name = "GOOSEDATA"
    fields_desc = [
                    XByteField("allData", 0xAB),
                    BERTotLenField("allData_Length", None)
                ]
    
    def guess_payload_class(self, payload):
        if len(payload) > 0:
            data = orb(payload[0])
            return data_types[data]
           
    def post_build(self, p, pay):
        p += pay
        tmp_bytes = vlenq2bytes(len(pay))
        p = p[:1] + tmp_bytes + p[1:]
        return p  


class GOOSEPDU(Packet):
    name = "GOOSEPDU"
    fields_desc = [
                    XByteField("gocbRef_Tag", 0x80),
                    BERLenQField("gocbRef_Length", None, "gocbRef"),
                    StrLenField("gocbRef", "TestLogic", length_from=lambda x:x.gocbRef_Length),
                    
                    XByteField("timeAllowedtoLive_Tag", 0x81),
                    BERLenQField("timeAllowedtoLive_Length", None, "timeAllowedtoLive"),
                    StrLenField("timeAllowedtoLive", "0", length_from=lambda x:x.timeAllowedtoLive_Length),
                    
                    XByteField("datSet_Tag", 0x82),
                    BERLenQField("datSet_Length", None, "datSet"),
                    StrLenField("datSet", "SimpleIO", length_from=lambda x:x.datSet_Length),
                    
                    XByteField("goID_Tag", 0x83),
                    BERLenQField("goID_Length", None, "goID"),
                    StrLenField("goID", "TestLogic", length_from=lambda x:x.goID_Length), 
                    
                    XByteField("t_Tag", 0x84),
                    BERLenQField("t_Length", None, "t"),
                    StrLenField("t", getTimestamp(), length_from=lambda x:x.t_Length),                                              

                    XByteField("stNum_Tag", 0x85),
                    BERLenQField("stNum_Length", None, "stNum"),
                    StrLenField("stNum", "0", length_from=lambda x:x.stNum_Length),
                    
                    XByteField("sqNum_Tag", 0x86),
                    BERLenQField("sqNum_Length", None, "sqNum"),
                    StrLenField("sqNum", "0", length_from=lambda x:x.sqNum_Length),
                    
                    XByteField("test_Tag", 0x87),
                    BERLenQField("test_Length", None, "test"),
                    StrLenField("test", '0', length_from=lambda x:x.test_Length),
                    
                    XByteField("confRev_Tag", 0x88),
                    BERLenQField("confRev_Length", None, "confRev"),
                    StrLenField("confRev", '0', length_from=lambda x:x.confRev_Length),
                    
                    XByteField("ndsCom_Tag", 0x89),
                    BERLenQField("ndsCom_Length", None, "ndsCom"),
                    StrLenField("ndsCom", "", length_from=lambda x:x.ndsCom_Length),
         
                    XByteField("numDataSetEntries_Tag", 0x8A),
                    BERLenQField("numDataSetEntries_Length", None, "numDataSetEntries"),
                    StrLenField("numDataSetEntries", "", length_from=lambda x:x.numDataSetEntries_Length),
                  ]

class GOOSE(Packet):
    name = "GOOSE"
    fields_desc = [ ShortField("APPID", 1000),
                    ShortField("Length", None),
                    ShortField("Reserved1", 0),
                    ShortField("Reserved2", 0),
                    XByteField("goosePDU_Tag", 0x61),
                    BERTotLenField("goosePDU_Length", None),
                  ]
        
    def post_build(self, p, pay):
        pad = bytes(1)
        p += pay
        if self.Length is None:
            tmp_len = len(p) - 2
            tmp_bytes = vlenq2bytes(tmp_len)
            if len(tmp_bytes) == 1:
                p = p[:2] + pad + tmp_bytes + p[4:]
            else:
                p = p[:2] + tmp_bytes + p[4:]
        if self.goosePDU_Length is None:
            tmp_len = tmp_len - 5
            tmp_bytes = vlenq2bytes(tmp_len)
            if len(tmp_bytes) == 1:
                p = p[:9] + tmp_bytes + p[9:]
            else:
                p = p[:9] + tmp_bytes + p[9:]

        return p  
    

bind_layers(Ether, GOOSE, type=0x88b8)
bind_layers(GOOSE, GOOSEPDU)
bind_layers(GOOSEPDU, GOOSEDATA)

if __name__ == "__main__":
    a = Ether(type="VLAN", dst='01:0c:cd:01:00:01')/Dot1Q(prio=4, vlan=0)/GOOSE(APPID = 0x03e8, Reserved1 =0, Reserved2=0)/GOOSEPDU(numDataSetEntries = b'\x01')/GOOSEDATA()/GooseInteger(Data=b'\x80')
    a.show2()
    sendp(a)