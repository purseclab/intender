import threading, sys, datetime
from . import PathService
from thrift.protocol import TBinaryProtocol
from thrift.transport import TSocket


class PathServiceClient():
    def __init__(self, hostname='localhost', port=9090, log=None):
        self.hostname = hostname
        self.port = port
        self.transport = TSocket.TSocket(hostname, port)
        self.protocol = TBinaryProtocol.TBinaryProtocol(self.transport)
        self.client = PathService.Client(self.protocol)
        self.log = log
        if log is not None:
            log.info("Path Service Client is created")
        #sys.stderr = open('/dev/null', 'w')

    def connect(self):
        startDate = datetime.datetime.now()
        expSecs = 0
        while True:
            try:
                self.transport.open()
                if self.log is not None:
                    self.log.info("Path Service Client is connected :)")
                break
            except:
                timeDiff = datetime.datetime.now() - startDate
                tsecs = timeDiff.total_seconds()
                if expSecs < tsecs and self.log is not None:
                    self.log.warn(f"Could not open the connection to PathServer! ({tsecs}s)")
                    expSecs += 1

    def close(self):
        try:
            self.transport.close()
        except:
            print("Could not close the connection to the PathServer")

    def find_path(self, dpid, egress_port, packet_header):
        return self.client.findPaths(dpid, egress_port, packet_header)

