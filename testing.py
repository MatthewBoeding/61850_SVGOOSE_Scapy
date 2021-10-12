from svGooseLib import goose, smv
from scapy.sendrecv import sendp
from scapy.layers.l2 import Ether, Dot1Q

if __name__ == '__main__':
    a = Ether(type = "VLAN", dst = '01:1C:CD:01:00:00')/Dot1Q(prio=4, vlan=0)/smv.SMV(noASDU = b'\x01')/smv.ASDU()
    sendp(a, verbose=False)
    b = Ether(type="VLAN", dst='01:0c:cd:01:00:01')/Dot1Q(prio=4, vlan=0)/goose.GOOSE(APPID = 0x03e8)\
        /goose.GOOSEPDU(test = b'\x00', confRev = b'\x00', ndsCom = b'\x00', numDataSetEntries = b'\x01')/goose.GOOSEDATA()/goose.GooseInteger(Data=b'\x80')
    sendp(b, verbose=False)
