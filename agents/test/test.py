#!/usr/bin/python

from optparse import OptionParser
from topo import TestMininet
import os

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
            metavar="IP", default="10.0.2.0/24")

    (options, args) = parser.parse_args()

    tm = TestMininet(os.getcwd()+'/..')
    tm.startMininet(options)
