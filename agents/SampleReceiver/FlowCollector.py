import socketserver
import time
import xdrlib

global recvqueue

class FlowC(socketserver.BaseRequestHandler):

    def handle(self):
        #print "Flow collector statred"
        datagram = self.receive_and_decode()
        #print "Flow Collector: received and decoded an sflow packet putting in the queue"
        recvqueue.put(datagram)
        #print "Flow Collector: a packet was sent to consistency tester"

    def decode_sflow_packet(self, payload):
        SFLOW_SAMPLE_TYPES = {'flow': 1,'counter': 2}

        """
        Decode an sFlow v5 'flow' packet and return a dict representation.
        >>> packet = '\x00\x00\x00\x05\x00\x00\x00\x01\x7f\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x13\x88\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00d\x00\x00\x00\x01\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00?\xff\xff\xff\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00<\x00\x00\x00\x01\x00\x00\x00.\x00\x00\x00\x04\x00\x00\x00*\xff\xff\xff\xff\xff\xff\xab\xab\xab\xab\xab\xab\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\xab\xab\xab\xab\xab\xab\xc0\x00\x02\x02\x00\x00\x00\x00\x00\x00\xc0\x00\x02\x01\x00\x00'
        >>> collector = FlowCollector()
        >>> collector._decode_sflow_packet(packet)
        {'address_family': 1,
         'agent_address': 2130706689,
         'decoded_at': 1430435127.716034,
         'samples': [{'drops': 0,
                      'flows': [{'frame_length': 46,
                                 'payload': '\xff\xff\xff\xff\xff\xff\xab\xab\xab\xab\xab\xab\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\xab\xab\xab\xab\xab\xab\xc0\x00\x02\x02\x00\x00\x00\x00\x00\x00\xc0\x00\x02\x01',
                                 'protocol': 1,
                                 'stripped': 4}],
                      'input': 1073741823,
                      'output': 4,
                      'sample_pool': 1,
                      'sampling_rate': 1,
                      'sequence_number': 1,
                      'source_id': 4}],
         'sequence_number': 2,
         'sflow_version': 5,
         'sub_agent_id': 0,
         'uptime': 5000}
        """

        payload = xdrlib.Unpacker(payload)
        packet = {}

        packet['decoded_at'] = time.time()
        packet['sflow_version'] = payload.unpack_int()
        packet['address_family'] = payload.unpack_int()
        packet['agent_address'] = payload.unpack_uint()
        packet['sub_agent_id'] = payload.unpack_uint()
        packet['sequence_number'] = payload.unpack_uint()
        packet['uptime'] = payload.unpack_uint()
        packet['samples'] = []

        # sflow packets will contain one or more "sample" records of various
        # types (e.g. flows, interface counters etc)
        n_samples = payload.unpack_uint()
        for i in range(n_samples):
            sample_type = payload.unpack_uint()
            sample_data = xdrlib.Unpacker(payload.unpack_opaque())

            # only process 'flow' type samples
            # XXX maybe implement other sample types
            if sample_type != SFLOW_SAMPLE_TYPES['flow']:
                continue

            sample = {}

            sample['sequence_number'] = sample_data.unpack_uint()
            sample['source_id'] = sample_data.unpack_uint()
            sample['sampling_rate'] = sample_data.unpack_uint()
            sample['sample_pool'] = sample_data.unpack_uint()
            sample['drops'] = sample_data.unpack_uint()
            sample['input'] = sample_data.unpack_uint()
            sample['output'] = sample_data.unpack_uint()
            sample['flows'] = []

            # "flow"-type samples contain one or more "flows" (truncated
            # packets sampled off the wire w/ metadata)
            n_flows = sample_data.unpack_uint()
            for j in range(n_flows):
                # flow_type is unused, but we need to unpack it anyway to
                # get to the next thing.
                flow_type = sample_data.unpack_uint()
                flow_data = xdrlib.Unpacker(sample_data.unpack_opaque())

                flow = {}

                flow['protocol'] = flow_data.unpack_int()
                flow['frame_length'] = flow_data.unpack_uint()
                flow['stripped'] = flow_data.unpack_uint()
                flow['payload'] = flow_data.unpack_opaque()

                sample['flows'].append(flow)

            packet['samples'].append(sample)

        return packet

    def receive_and_decode(self):
        data = self.request[0]
        return self.decode_sflow_packet(data)
