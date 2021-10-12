from scapy.packet import Packet, bind_layers
from scapy.fields import XByteField, FieldLenField, StrLenField, ShortField, UTCTimeField, Field
from scapy.layers.l2 import Ether, Dot1Q
from scapy.compat import raw

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

class ASDU(Packet):
    name = "ASDU"
    fields_desc = [ XByteField("ASDU_Tag", 0x30),
                    BERTotLenField("ASDU_Length", None),
                    
                    XByteField("svID_Tag", 0x80),
                    BERLenQField("svID_Length", None, "svID"),
                    StrLenField("svID", "sv tst", length_from=lambda x:x.svID_Length),
                    
                    XByteField("smpCnt_Tag", 0x82),
                    BERLenQField("smpCnt_Length", None, "smpCnt"),
                    StrLenField("smpCnt", "1", length_from=lambda x:x.smpCnt_Length),

                    XByteField("confRev_Tag", 0x83),
                    BERLenQField("confRev_Length", None, "confRev"),
                    StrLenField("confRev", "1", length_from=lambda x:x.confRev_Length),

                    XByteField("smpSynch_Tag", 0x85),
                    BERLenQField("smpSynch_Length", None, "smpSynch"),
                    StrLenField("smpSynch", "1", length_from=lambda x:x.smpSynch_Length),

                    XByteField("SeqData_Tag", 0x87),
                    BERLenQField("SeqData_Length", None, "SeqData"),
                    StrLenField("SeqData", "test", length_from=lambda x:x.SeqData_Length)
        ]
    
    def guess_payload_class(self, payload):
        if len(payload) > 0:
            return ASDU
        
    def post_build(self, p, pay):
        p += pay
        if self.ASDU_Length is None:
            tmp_len = len(p) - len(pay) - 1
            tmp_bytes = vlenq2bytes(tmp_len)
            p = p[:1] + tmp_bytes + p[1:]
        return p
    
class SMV(Packet):
    name = "SMV"
    fields_desc = [ ShortField("APPID", 3),
                    ShortField("Length", None),
                    ShortField("Reserved1", 0),
                    ShortField("Reserved2", 0),
                    XByteField("savPDU_Tag", 0x60),
                    BERTotLenField("savPDU_Length", None),
                    XByteField("noASDU_Tag", 0x80),
                    BERLenQField("noASDU_Length", None, "noASDU"),
                    StrLenField("noASDU", "", length_from=lambda x:x.noASDU_Length),
                    XByteField("SeqASDU", 0xa2),
                    BERTotLenField("SeqADSU_Length", None)
                  ]

    def post_build(self, p, pay):
        p += pay
        #self.len must be 2 bytes
        if self.Length is None:
            tmp_len = len(p) - 2
            tmp_bytes = vlenq2bytes(tmp_len)
            if len(tmp_bytes) > 2:
                tmp_bytes = b'\xff\xff'
            if len(tmp_bytes) < 2:
                tmp_bytes = b'\x00' + tmp_bytes
            p = p[:2] + tmp_bytes + p[4:]
        #The savPDU length will always be 5 bytes less due to Reserved + tag field
        if self.savPDU_Length is None:
            tmp_len = tmp_len - 5
            tmp_bytes = vlenq2bytes(tmp_len)
            placement = len(tmp_bytes) + 8
            p = p[:placement] + tmp_bytes + p[placement:]
        if self.SeqADSU_Length is None:
            tmp_len = len(pay)
            tmp_bytes = vlenq2bytes(tmp_len)
            p = p[:len(p)-len(pay)] + tmp_bytes + p[len(p)-len(pay):]
        return p
    
bind_layers(Ether, SMV, type=0x88ba)
bind_layers(SMV, ASDU)

if __name__ == "__main__":
    a = Ether(type = "VLAN", dst = '01:1C:CD:01:00:00')/Dot1Q(prio=4, vlan=0)/SMV()/ASDU()
    a.show()
