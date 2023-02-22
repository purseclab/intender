import queue
import socketserver
import struct
import threading
import timeit
import datetime
import time
import random
import multiprocessing
import subprocess
import socket
import httplib2
import json
from util import agentlogging

from searchservice import pathServiceClient
from SampleReceiver import FlowCollector
from netaddr.strategy.ipv4 import *
from threading import Thread
from multiprocessing import Process
from collections import OrderedDict
import six.moves.urllib.parse as urlparse
from bloom import bloom

log = agentlogging.getLogger(__name__, '/tmp/ifuzzer/ct-agent.log')
VERIFY_ETHER_TYPE = 2080
HEADERS_LIST = []

class CTCache():
    def __init__(self, maxLen):
        self.maxLen = maxLen
        self.cache = OrderedDict()

    def get_item(self, idx):
        if idx in self.cache:
            self.cache.move_to_end(idx)
            return self.cache[idx]
        return None

    def set_item(self, idx, val):
        if len(self.cache) >= self.maxLen:
            self.cache.popitem(False)
        self.cache[idx] = val

    def __str__(self):
        return self.cache.__str__()

    def __len__(self):
        return self.cache.__len__()

    def __contains__(self, key):
        return key in self.cache

    def clear(self):
        self.cache.clear()

class ConsistencyTester:

    ''' Simple Stat '''
    sampleCntByDst = {}
    sampleCntByRule = {}
    crc16cache = CTCache(1024)
    pathCache = CTCache(128)

    '''
    If net exist,  net.rootIP
    Otherwise, use serverIP
    '''
    def __init__(self, net, options, path, serverIP=None):
        self.net = net
        self.options = options
        self.path = path
        self.serverIP = serverIP
        self.ret_url = None
        if serverIP is not None:
            self.ret_url = urlparse.urlunsplit(('http', f'{serverIP}:5000', '/pazz_result', '', ''))
        elif net is not None:
            self.ret_url = urlparse.urlunsplit(('http', f'{net.rootIP}:5000', '/pazz_result', '', ''))
            self.serverIP = "localhost"

    def init(self):
        log.debug("cleared.")
        self.pathCache.clear()

    def getDpPortBysFlowIdx(self, idx):
        if self.net is not None:
            switch, port = self.net.getTestPointByIdx(idx)

            # switch can be none, if sample comes during finializing
            if switch is None:
                return None, None

            return "of:" + switch.dpid, port

        if self.serverIP is None:
            return None, None

        # GET://sflow/<idx>
        try:
            h = httplib2.Http(timeout=5)
            resp, content = h.request(f"http://{self.serverIP}:5000/sflow/{idx}", method='GET')

            if resp.status != 200:
                LOG.error(f"fail to request sflow [{idx}] to {self.serverIP}")
                return None, None

            content = json.loads(content.decode("utf-8"))
            return content["switch"], content["port"]

        except Exception:
            LOG.error(f"fail to request sflow [{idx}] to {self.serverIP}")

        return None, None


    def extract_header(self, payload):
        if len(payload) >= 42:
            offset = 12
            verify_header_ether_type = struct.unpack_from("!H", payload, offset=offset)[0]
            if verify_header_ether_type != VERIFY_ETHER_TYPE:
                return None, None, None, None
            offset += 2
            verify_rule, verify_port, ether_type, version, \
            tos, total_length, identification, flags, ttl, proto, csum, src, dst \
                = struct.unpack_from('!HLHBBHHHBBH4s4s', payload, offset=offset)
            dst_ip = int_to_bits(packed_to_int(dst)).replace(".", "")
            return dst_ip, socket.inet_ntoa(dst), verify_rule, verify_port
        return None, None, None, None

    def crc16(self, dpid, rule, basis):
        cid = f"{dpid}/{rule}/{basis}"

        if cid in self.crc16cache:
            return self.crc16cache.get_item(cid)

        crc16cmd = self.path + "/util/run-crc16"
        p = subprocess.Popen([crc16cmd, f"{dpid}", f"{rule}", f"{basis}"],
                stdout=subprocess.PIPE)
        basis, err = p.communicate()

        self.crc16cache.set_item(cid, int(basis))
        return int(basis)

    def test_consistency(self):
        global recvqueue, log

        if self.serverIP is not None:
            path_service_client = pathServiceClient.PathServiceClient(hostname=self.serverIP, log=log)
            path_service_client.connect()

        prevHeader = None
        prevDstIp = None
        prevVerifyRule = None
        prevVerifyPort = None
        while True:
            #self.output.write("Sample Pull timestamp %s >>>\n" % str(time))
            packet = recvqueue.get()

            switchDpid, egress_port = self.getDpPortBysFlowIdx(packet['sub_agent_id'])
            if switchDpid is None:
                log.warn(f"Cannot find sflow agent: id {packet['sub_agent_id']}")
                continue

            for sample in packet['samples']:
                in_port = sample['input']
                #self.output.write(f"Sample from {switchDpid}:{egress_port}\n")
                #self.output.flush()

                if not in_port:
                    continue

                for flow in sample['flows']:
                    if flow is None or flow['payload'] is None:
                        continue

                    header, dst_ip, verify_rule, verify_port = self.extract_header(flow['payload'])
                    if header is None:
                        continue

                    isNewDst = False
                    if dst_ip not in self.sampleCntByDst:
                        log.info(f"New dst: {dst_ip}, verify_rule: {verify_rule}, verify_port: {verify_port} from {switchDpid}:{egress_port}")
                        self.sampleCntByDst[dst_ip] = 0
                        isNewDst = True
                    self.sampleCntByDst[dst_ip] += 1

                    ruleId = str(verify_rule)
                    if ruleId not in self.sampleCntByRule:
                        if not isNewDst:
                            log.info(f"New verify_rule: {dst_ip}, verify_rule: {verify_rule}, verify_port: {verify_port} from {switchDpid}:{egress_port}")
                        self.sampleCntByRule[ruleId] = 0
                    self.sampleCntByRule[ruleId] += 1

                    if self.serverIP is None:
                        continue

                    # Do cache for fast handling
                    if str(prevHeader) == str(header) and \
                            str(prevDstIp) == str(dst_ip) and \
                            str(prevVerifyRule) == str(verify_rule) and \
                            str(prevVerifyPort) == str(verify_port):
                        continue

                    prevHeader = header
                    prevDstIp = dst_ip
                    prevVerifyRule = verify_rule
                    prevVerifyPort = verify_port

                    pathId = f"{switchDpid}/{egress_port}/{header}"
                    #print "Header: %s, verify_rule: %s, verify_port: %s\n" % (header, verify_rule, verify_port))
                    if pathId in self.pathCache:
                        expected_paths = self.pathCache.get_item(pathId)
                    else:
                        expected_paths = path_service_client.find_path(switchDpid, int(egress_port), header)
                        self.pathCache.set_item(pathId, expected_paths)

                    #self.output.write(f"{expected_paths}\n")
                    expected_rules = expected_paths[1:len(expected_paths) // 2]
                    expected_ports = expected_paths[len(expected_paths) // 2 + 1:]
                    #self.output.write("ER: %s, EP: %s\n" % (expected_rules, expected_ports))
                    #self.output.flush()

                    expected_rule_hashes = []

                    #timer = timeit.default_timer()
                    localization_time = []
                    detection_time = 0
                    for rules in reversed(expected_rules):
                        hash = 1
                        local_rule_id = None
                        for r in reversed((rules[1:len(rules) - 1]).strip().split(",")):
                            r = r.strip()
                            if local_rule_id is None:
                                local_rule_id = r
                                continue
                            dpid = r
                            hash = self.crc16(dpid, local_rule_id, hash)
                            expected_rule_hashes.append(int(hash))
                            local_rule_id = None

            # =================== Detection ==========================
                    if verify_rule in expected_rule_hashes:
                        continue

                    detection_time = datetime.datetime.now().strftime('%H:%M:%S.%f')
                    #localization_time = []
                    #expected_port_bloom = []
                    #EB = None
                    #AB = None
                    #Diff = None
            # =================== Localization =======================
                    #timer = timeit.default_timer()
                    #self.output.write("ER: %s, EP: %s\n" % (expected_rules, expected_ports))

                    for ports in reversed(expected_ports):
                        Bloom = 0       # was 1
                        localization = 0
                        #round = 0
                        local_port_id = None
                        for p in reversed((ports[1:len(ports) - 1]).strip().split(",")):
                            p = p.strip()
                            if local_port_id is None:
                                local_port_id = p
                                continue
                            dpid = p
                            Bloom = bloom(Bloom, int(dpid), int(p))
                            local_port_id = None

                            #expected_port_bloom.append(Bloom)
                            diff = Bloom & verify_port
                            #self.output.write("Port: %s\n" % p)
                            #self.output.write("Bloom: %s\n" % Bloom)
                            #self.output.write("diff: %s\n" % diff)
                            if diff == Bloom:
                                continue

                            #localization_time.append( (int(p), timeit.default_timer() - timer) )
                            localization = datetime.datetime.now().strftime('%H:%M:%S.%f')
                            #localization = str(localization.minute) + ':' + str(localization.second) + '.' + str(localization.microsecond)
                            localization_time.append(localization)
                            break
                                #self.output.write("%s; %s; %s; %s\n" % (header, expected_ports[::-1], detection_time, localization_time) )
                    # FIND ERROR!
                    resp_code = self.sendError(switchDpid, egress_port)

                    log.warn(f"{detection_time}/{localization_time} {self.ret_url} [{resp_code}]: {dst_ip}\n")
                #EB = bin(Bloom)[2:].zfill(32)
                                    #AB = bin(verify_port)[2:].zfill(32)
                                    #Diff = bin(diff)[2:].zfill(32)
                                #round = round + 1


    def sendError(self, dpid, port):
        if self.serverIP is None:
            return -1

        jsonBody = {}
        jsonBody["agent"] = "CT"
        jsonBody["receiver"] = dpid + "/" + port
        jsonBody["result"] = "fail"
        h = httplib2.Http(timeout=5)
        resp, content = h.request(self.ret_url, method="POST",
                headers={"Content-type": "application/json"},
                body=json.dumps(jsonBody))

        return resp.status


    def run(self):
        global recvqueue, log
        log.info("run ConsistencyTester");

        recvqueue = queue.Queue(maxsize=0)
        FlowCollector.recvqueue = recvqueue
        socketserver.UDPServer.allow_reuse_address = True

        flow_collector = socketserver.UDPServer(("0.0.0.0", 6343), FlowCollector.FlowC)
        flow_collector_thread = threading.Thread(target=flow_collector.serve_forever)
        flow_collector_thread.setDaemon(True)
        flow_collector_thread.start()
        log.info("run Flow Collector");

        self.thread = threading.Thread(target=self.test_consistency)
        self.thread.setDaemon(True)
        self.thread.start()
