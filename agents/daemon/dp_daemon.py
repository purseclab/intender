from util.daemon import Daemon
from flask import Flask, Response
from flask.globals import request
from scapy.all import *
from scapy.utils import get_temp_file, wrpcap
import subprocess, logging, json, threading, httplib2, os, signal, multiprocessing

LOG = logging.getLogger(__name__)
api = Flask(__name__)
replayProcList = {}
iface = None
pcap = None
pps = 1000
ppsMulti = 1000
sniffThreadList = {}

def exec_tcpreplay(src, dst, iface):
    global pps, ppsMulti
    argv = ['tcpreplay']
    argv.append(f"--intf1={iface}")
    argv.append(f"--pps={pps}")
    argv.append(f"--pps-multi={ppsMulti}")
    argv.append("--loop=0")
    argv.append("--preload-pcap")

    pkt = Ether(src='70:88:99:00:11:22', dst='10:22:33:44:55:66')/IP(src=src, dst=dst)/TCP(sport=50000, dport=1234)
    f = get_temp_file()
    argv.append(f)
    wrpcap(f, pkt)

    return subprocess.Popen(argv, stdout=subprocess.PIPE,
            preexec_fn=os.setsid)


def handle_sniff(pkt, ip_proto, req_body):
    print("[sniff receiver]", pkt.summary())
    src = req_body["src"]
    dst = req_body["dst"]

    if (ip_proto == 17) and (UDP in pkt):
        rcvSrc = pkt.getlayer(IP).src
        if rcvSrc != src:
            return
        rcvDst = pkt.getlayer(IP).dst
        if rcvDst != dst:
            return

        # TODO: compare payload

    elif (ip_proto == 6) and (TCP in pkt):
        rcvSrc = pkt.getlayer(IP).src
        if rcvSrc != src:
            return
        rcvDst = pkt.getlayer(IP).dst
        if rcvDst != dst:
            return

        # TODO: compare payload

    elif (ip_proto == 1) and (ICMP in pkt):
        ''' matched '''

    elif (ip_proto == 0x84) and (SCTP in pkt):
        ''' matched '''

    else:
        return

    req_body["result"] = "success"

    # NOTE: it does not make a response for uncaptured packet.
    if "ret_url" in req_body:
        ret_url = req_body["ret_url"]
        h = httplib2.Http(timeout=5)
        resp, content = h.request(ret_url, method="POST",
                headers={"Content-type": "application/json"},
                body=json.dumps(req_body))
        print(ret_url, json.dumps(req_body), resp.status)

def sniff_task(ip_proto, req_body):
    global iface
    src = req_body["src"]
    dst = req_body["dst"]

    target_iface = iface
    if "iface" in req_body:
        target_iface = req_body["iface"]

    filterStr="ip proto " + str(ip_proto) + " and src " + src + " and dst " + dst

    pkt = sniff(iface=target_iface, prn=lambda x: handle_sniff(x, ip_proto, req_body),
            filter=filterStr,
            count=1, timeout=2)
    print("[sniff thread]", filterStr, pkt)


''' REST APIs '''

@api.route('/ping', methods=['POST'])
def ping_host():
    req_body = request.get_json()
    src = req_body["src"]
    dst = req_body["dst"]

    ret = subprocess.call(['ping', '-c', '1', '-w' '1', dst])
    if ret == 0:
        status_code = 200
        result = "success"
    elif ret == 1:
        status_code = 408
        result = "fail"
    elif ret == 2:
        status_code = 404
        result = "fail"
    else:
        status_code = 400
        result = "fail"

    return Response(response=json.dumps([{"src": src, "dst": dst, "result": result}]), status=status_code, mimetype='application/json')

@api.route('/send', methods=['POST'])
def send_host():
    global iface
    req_body = request.get_json()
    src = req_body["src"]
    dst = req_body["dst"]

    target_iface = iface
    if "iface" in req_body:
        target_iface = req_body["iface"]

    cnt = 1
    if "cnt" in req_body:
        cnt = req_body["cnt"]

    criteria = []
    ipProto = 17
    if "criteria" in req_body:
        criteria = req_body["criteria"]

        for criterion in criteria:
            if ("type" in criterion) and (criterion["type"] == "IP_PROTO"):
                ipProto = criterion["protocol"]

    # TODO: set ethernet address
    pkt = Ether()
    if "ethDst" in req_body:
        pkt = Ether(dst=req_body["ethDst"])

    if ipProto == 6:
        # work-around
        sendp(pkt/IP(src=src, dst=dst)/TCP(sport=50000, dport=1234), iface=target_iface, count=cnt)
    elif ipProto == 17:
        sendp(pkt/IP(src=src, dst=dst)/UDP(sport=50000, dport=1234), iface=target_iface, count=cnt)
    elif ipProto == 1:
        sendp(pkt/IP(src=src, dst=dst)/ICMP(), iface=target_iface, count=cnt)
    elif ipProto == 0x84:
        sendp(pkt/IP(src=src, dst=dst)/SCTP(), iface=target_iface, count=cnt)

    print("[POST://send]", src, dst)

    return Response(response=json.dumps([{"src": src, "dst": dst, "result": "success"}]), status=200, mimetype='application/json')

@api.route('/sniff', methods=['POST'])
def sniff_host():
    global iface, sniffThreadList
    req_body = request.get_json()
    src = req_body["src"]
    dst = req_body["dst"]
    seq = req_body["seq"]
    key = req_body["key"]

    criteria = []
    ipProto = 17
    if "criteria" in req_body:
        criteria = req_body["criteria"]

        for criterion in criteria:
            if ("type" in criterion) and (criterion["type"] == "IP_PROTO"):
                ipProto = criterion["protocol"]

    target_iface = iface
    if "iface" in req_body:
        target_iface = req_body["iface"]

    filterStr="ip proto " + str(ipProto) + " and src " + src + " and dst " + dst

    print(f"[POST://sniff] src:{src}, dst: {dst}, ip_proto: {ipProto}, # of criteria: {len(criteria)}")
    thread = AsyncSniffer(iface=target_iface, prn=lambda x : handle_sniff(x, ipProto, req_body),
            filter=filterStr, count=1, timeout=2)
    # thread = threading.Thread(target=sniff_task, kwargs={'ip_proto': ipProto, 'req_body': req_body})

    try:
        tmpThread = sniffThreadList[key + seq]
        print(f"Stop sniffThread with {key}:{seq}")
        sniffThreadList.pop(key + seq)
        tmpThread.stop()
    except KeyError as ke:
        ''' Not Found '''
    except Scapy_Exception as se:
        ''' Not running '''

    sniffThreadList.update({key+seq:thread})
    thread.start()
    return Response(response=json.dumps([{"src": src, "dst": dst, "result": "success"}]),
            status=200, mimetype='application/json')

@api.route('/stopsniff', methods=['POST'])
def stop_sniff_host():
    global iface, sniffThreadList
    req_body = request.get_json()
    seq = req_body["seq"]
    key = req_body["key"]

    try:
        tmpThread = sniffThreadList[key + seq]
        print(f"Stop sniffThread with {key}:{seq}")
        sniffThreadList.pop(key + seq)
        tmpThread.stop()
    except KeyError as ke:
        ''' Not Found '''
    except Scapy_Exception as se:
        ''' Not running '''

    return Response(response=json.dumps([{"seq": seq, "key": key, "result": "success"}]),
            status=200, mimetype='application/json')


@api.route('/genreplay', methods=['POST'])
def gen_tcpreplay():
    global iface, replayProcList
    req_body = request.get_json()
    seq = req_body["seq"]
    key = req_body["key"]

    # TODO: make src and dst as lists
    src = req_body["src"]
    dst = req_body["dst"]

    ''' TODO: manage tcpreplay process by seq+key '''
    target_iface = iface
    if "iface" in req_body:
        target_iface = req_body["iface"]

    if key + seq in replayProcList:
        replayProc = replayProcList.pop(key + seq)
        os.killpg(os.getpgid(replayProc.pid), signal.SIGTERM)
    replayProcList[key + seq] = exec_tcpreplay(src, dst, network_name(target_iface))

    return Response(response=json.dumps([{"seq": seq, "key": key, "result": "success"}]),
            status=200, mimetype='application/json')

@api.route('/stopreplay', methods=['POST'])
def stop_tcpreplay():
    ''' kill tcpreplay '''
    global replayProcList
    req_body = request.get_json()
    seq = req_body["seq"]
    key = req_body["key"]

    if key + seq not in replayProcList:
        return Response(response=json.dumps([{"seq": seq, "key": key, "result": "no tcpreplay process"}]),
           status=404, mimetype='application/json')

    replayProc = replayProcList.pop(key + seq)
    print(f"Try to kill {replayProc.pid}")
    os.killpg(os.getpgid(replayProc.pid), signal.SIGTERM)
    tmpOut, tmpErr = replayProc.communicate()

    return Response(response=json.dumps([{"seq": seq, "key": key, "result": "success"}]),
            status=200, mimetype='application/json')


# @app.route('/<path:url>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
# def handle_request(url):
#     return RestHandler(request).handle_proxy()
#
# class RestHandler(object):
#
#     def __init__(self, request):
#         LOG.debug(f'HTTP request: {request}')
#         self.req = request
#
#     def handle_proxy(self):
#         path = 'ping/%s' % ()
#         try:
#             return self._handle_proxy(self.req)
#         except Exception as E:
#             LOG.error(f'exception happens in _handle_proxy: {str(E)}')
#             return 'failed', INTERNAL_SERVER_ERROR
#
#     def _hande_proxy(self, req):


class DpDaemon(Daemon):
    def __init__(self, options, pidfile, processname='', logfile='/dev/null'):
        super(DpDaemon, self).__init__(pidfile, processname,
                stdout=logfile, stderr=logfile)
        global iface, pcap, pps, ppsMulti
        iface = options.iface
        pcap = options.pcap
        pps = options.pps
        ppsMulti = options.ppsMulti
        self.callback = options.callback

    def run(self):
        thread = threading.Thread(target=api.run, kwargs={'host': '0.0.0.0'})
        thread.start()

        if self.callback is not None:
            try:
                h = httplib2.Http(timeout=5)
                resp, content = h.request(self.callback, method='GET')
            except Exception:
                ''' connection fails '''

class DpFgDaemon():
    def __init__(self, options):
        global iface, pcap, pps, ppsMulti
        iface = options.iface
        pcap = options.pcap
        pps = options.pps
        ppsMulti = options.ppsMulti
        self.callback = options.callback

    def start(self):
        thread = threading.Thread(target=api.run, kwargs={'host': '0.0.0.0'})
        thread.start()

        if self.callback is not None:
            try:
                h = httplib2.Http(timeout=5)
                resp, content = h.request(self.callback, method='GET')
            except Exception:
                ''' connection fails '''

    def stop(self):
        ''' Do nothing '''

    def restart(self):
        ####### TODO #######
        ''' Do nothing '''

    def status(self):
        ''' Do nothing '''
