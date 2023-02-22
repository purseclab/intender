import os, sys
from optparse import OptionParser
from daemon.consistencyTester import ConsistencyTester

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("-s", "--serverIP", dest="serverIP",
            help="specify the IP of server (fuzzer)",
            metavar="URL")
    parser.add_option("--path", dest="agent_path",
            help="specify path of agents",
            metavar="PATH", default=os.getcwd())

    (options, args) = parser.parse_args()

    if (len(args) >= 1):
        agentCmd = args[0]
    else:
        print(f"Usage: python {sys.argv[0]} <start|stop|restart|status> [options]")
        sys.exit(2)

    ct = ConsistencyTester(None, options, options.agent_path, options.serverIP)

    if agentCmd == 'start':
#sys.stderr = open('/dev/null', 'w+')
        ct.run()
    else:
        print(f"Usage: python {sys.argv[0]} <start|stop|restart|status>")
        sys.exit(2)
