import sys
from daemon.dp_daemon import DpDaemon
from daemon.dp_daemon import DpFgDaemon
from optparse import OptionParser

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("-F", "--fg", dest="fg",
            help="run foreground",
            action="store_true", default=False)
    parser.add_option("-i", "--iface", dest="iface",
            help="specify data interface")
    parser.add_option("-n", "--name", dest="name",
            help="specify hostname which runs dp-agent")
    parser.add_option("-c", "--callback", dest="callback",
            help="specify callback url")
    parser.add_option("-p", "--pcap", dest="pcap",
            help="specify pcap file")
    parser.add_option("--pps", dest="pps",
            help="specify pps option of tcpreplay",
            metavar="INTEGER", type="int", default=100)
    parser.add_option("--pps-multi", dest="ppsMulti",
            help="specify pps-multi option of tcpreplay",
            metavar="INTEGER", type="int", default=100)

    (options, args) = parser.parse_args()

    if (len(args) >= 1):
        agentCmd = args[0]
    else:
        print(f"Usage: python {sys.argv[0]} <start|stop|restart|status> [-F]")
        sys.exit(2)

    if options.fg:
        dpDaemon = DpFgDaemon(options)
    else:
        if options.name is None:
            print(f"Error: run daemon with -n (--name) option")
            sys.exit(2)
        dpDaemon = DpDaemon(options, f"/tmp/ifuzzer/dp-agent-{options.name}.pid",
                'IFuzzDPAgent', logfile=f"/tmp/ifuzzer/dp-agent-{options.name}.log")

    if agentCmd == 'start':
        dpDaemon.start()
    elif agentCmd == 'stop':
        dpDaemon.stop()
    elif agentCmd == 'restart':
        dpDaemon.restart()
    elif agentCmd == 'status':
        dpDaemon.status()
    else:
        print(f"Usage: python {sys.argv[0]} <start|stop|restart|status>")
        sys.exit(2)
