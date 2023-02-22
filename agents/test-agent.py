import os, sys
from daemon.test_daemon import TestDaemon, TestFgDaemon
from optparse import OptionParser

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("-c", "--controller", dest="controllers",
            help="specify the IP address of the controller",
            action="append", metavar="IP")
    parser.add_option("-s", "--switch", dest="switches",
            help="specify the number of switches",
            metavar="INTEGER", type="int", default=2)
    parser.add_option("-p", "--host", dest="hosts_per_switch",
            help="specify the number of hosts per leaf switch",
            metavar="INTEGER", type="int", default=2)
    parser.add_option("-t", "--topo", dest="topology",
            help="specify topology type")
    parser.add_option("-v", "--verbose", dest="verbose",
            help="display additional logging information",
            action="store_true", default=False)
    parser.add_option("-d", "--data_net", dest="data_net",
            help="specify data network",
            metavar="IP", default="10.0.0.0/24")
    parser.add_option("-m", "--mgmt_net", dest="mgmt_net",
            help="specify managment network",
            metavar="IP", default="10.0.10.0/24")
    parser.add_option("-f", "--fuzzer_url", dest="fuzzer_url",
            help="specify the url of fuzzer",
            metavar="URL")
    parser.add_option("-F", "--fg", dest="fg",
            help="run foreground",
            action="store_true", default=False)
    parser.add_option("--discover_host", dest="discover_host",
            help="specify to send initial packet",
            action="store_true", default=False)
    parser.add_option("--path", dest="agent_path",
            help="specify path of agents",
            metavar="PATH", default=os.getcwd())
    parser.add_option("-z", "--pazz", dest="pazzEnable",
            help="enable pazz-extension (verify field)",
            action="store_true", default=False)
    parser.add_option("--static_mirror", dest="staticMirrorEnable",
            help="enable mirror to H_PI from every S_PI",
            action="store_true", default=False)
    parser.add_option("-r", "--sample_rate", dest="sampleRate",
            help="set sample rate of sflow",
            metavar="INTEGER", type="int", default=100)
    parser.add_option("--ct", dest="ct",
            help="specify consistencyTester in local",
            metavar="IP")


    (options, args) = parser.parse_args()

    if (len(args) >= 1):
        agentCmd = args[0]
    else:
        print(f"Usage: python {sys.argv[0]} <start|stop|restart|status> [options]")
        sys.exit(2)

    if (options.controllers is None) or (len(options.controllers) == 0):
        options.controllers = ["127.0.0.1"]

    if options.fg:
        testDaemon = TestFgDaemon(options, path=options.agent_path)
    else:
        testDaemon = TestDaemon(options, '/tmp/ifuzzer/test-agent.pid',
                'IFuzzTestAgent', path=options.agent_path)

    if agentCmd == 'start':
        testDaemon.start()

    elif agentCmd == 'stop':
        if testDaemon.stop():
            # XXX: it is useful when dp-agent is running in daemon
            # hostnames = []
            # try:
            #     hf = open(testDaemon.hostfile, 'r')
            #     hostnames = hf.read().strip().split(' ')
            #     os.remove(testDaemon.hostfile)
            # except IOError:
            #     ''' do nothing '''

            # for hostname in hostnames:
            #     os.system(f"python3 {options.agent_path}/dp-agent.py -n {hostname} stop")
            os.system("mn -c")

    elif agentCmd == 'restart':
        # TODO: support restart with stored argument
        if testDaemon.stop():
            os.system("mn -c")
        testDaemon.start()

    elif agentCmd == 'status':
        testDaemon.status()

    else:
        print(f"Usage: python {sys.argv[0]} <start|stop|restart|status>")
        sys.exit(2)
