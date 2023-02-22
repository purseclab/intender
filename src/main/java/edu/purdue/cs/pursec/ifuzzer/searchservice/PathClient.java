package edu.purdue.cs.pursec.ifuzzer.searchservice;

import org.apache.thrift.TException;
import org.apache.thrift.protocol.TBinaryProtocol;
import org.apache.thrift.protocol.TProtocol;
import org.apache.thrift.transport.TSSLTransportFactory;
import org.apache.thrift.transport.TSSLTransportFactory.TSSLTransportParameters;
import org.apache.thrift.transport.TSocket;
import org.apache.thrift.transport.TTransport;

public class PathClient {


    public PathClient() {
        // TODO Auto-generated constructor stub
    }

    public static void main(String [] args) {
        String arg[]= new String[1];
        args = arg;
        args[0] = "simple";

        try {
            TTransport transport;
            if (args[0].contains("simple")) {
                transport = new TSocket("localhost", 9090);
                transport.open();
            }
            else {
                /*
                 * Similar to the server, you can use the parameters to setup client parameters or
                 * use the default settings. On the client side, you will need a TrustStore which
                 * contains the trusted certificate along with the public key.
                 * For this example it's a self-signed cert.
                 */
                TSSLTransportParameters params = new TSSLTransportParameters();
                params.setTrustStore("../../lib/java/test/.truststore", "thrift", "SunX509", "JKS");
                /*
                 * Get a client transport instead of a server transport. The connection is opened on
                 * invocation of the factory method, no need to specifically call open()
                 */
                transport = TSSLTransportFactory.getClientSocket("localhost", 9091, 0, params);
            }

            TProtocol protocol = new TBinaryProtocol(transport);
            PathService.Client client = new PathService.Client(protocol);

            perform(client);

            transport.close();
        } catch (TException x) {
            x.printStackTrace();
        }
    }

    private static void perform(PathService.Client client) throws TException
    {
	    /*client.ping();
	    System.out.println("ping()");

	    int sum = client.add(1,1);
	    System.out.println("1+1=" + sum);

	    Work work = new Work();

	    work.op = Operation.DIVIDE;
	    work.num1 = 1;
	    work.num2 = 0;
	    try {
	      int quotient = client.calculate(1, work);
	      System.out.println("Whoa we can divide by 0");
	    } catch (InvalidOperation io) {
	      System.out.println("Invalid operation: " + io.why);
	    }

	    work.op = Operation.SUBTRACT;
	    work.num1 = 15;
	    work.num2 = 10;
	    try {
	      int diff = client.calculate(1, work);
	      System.out.println("15-10=" + diff);
	    } catch (InvalidOperation io) {
	      System.out.println("Invalid operation: " + io.why);
	    }

	    SharedStruct log = client.getStruct(1);
	    System.out.println("Check log: " + log.value);
	  }*/
        //System.out.println("The result is "+client.findPaths(1, "1"));
    }
}
