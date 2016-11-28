import pyshark







class SSLHandshakeDetector(object):
    def __init__(self):
        self.SSLConnections = []


    def findSSLConnections(self, interface):
        self.capturePacketsLive(interface)


    def capturePacketsLive(self, interface):
        capture = pyshark.LiveCapture(interface=interface, display_filter='ssl')

        for packet in capture.sniff_continuously():
                try:
                    print packet.ssl.handshake
                    #self.checkBelonging(packet)
                except:
                    continue


    def checkBelonging(self, packet):
        for connection in self.SSLConnections:
            if self.belongsTo(packet, connection):
                self.delegatePacket(packet, connection)



    def belongsTo(self, packet, connection):
        if ((packet.ip.dst == connection.ipParticipant1 and
             packet.ip.src == connection.ipParticipant2) or
            (packet.ip.dst == connection.ipParticipant2 and
             packet.ip.src == connection.ipParticipant1)):
            return True

        else:
            return False


class SSLConnection(object):
    def __init__(self):
        self.ipParticipant1 = None
        self.ipParticipant2 = None
        self.portParticipant1 = None
        self.portParticipant2 = None
        self.syn = 0
        self.synAck = 0
        self.ack = 0













if __name__ == "__main__":
    interface = 'enp3s0'
    outputFile = '/out.pcap'

    detector = SSLHandshakeDetector()
    detector.findSSLConnections(interface)