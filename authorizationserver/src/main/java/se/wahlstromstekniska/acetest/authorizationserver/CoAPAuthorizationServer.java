package se.wahlstromstekniska.acetest.authorizationserver;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;

import org.apache.log4j.Logger;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;

import se.wahlstromstekniska.acetest.authorizationserver.resource.IntrospectResource;
import se.wahlstromstekniska.acetest.authorizationserver.resource.TokenResource;


public class CoAPAuthorizationServer extends CoapServer {

	final static Logger logger = Logger.getLogger(CoAPAuthorizationServer.class);
	private static ServerConfiguration config = ServerConfiguration.getInstance();
	
	static CoAPAuthorizationServer server = null;
	
    public static void main(String[] args) throws Exception {
        try {
            logger.info("Starting server.");
            server = new CoAPAuthorizationServer();
        	server.start();
        } catch (SocketException e) {
            System.err.println("Failed to initialize server: " + e.getMessage());
        }
    }
 
    /*
     * Constructor.
     */
    public CoAPAuthorizationServer() throws SocketException {
        add(new TokenResource());
        add(new IntrospectResource());
 
    	for (InetAddress addr : EndpointManager.getEndpointManager().getNetworkInterfaces()) {
    		// only binds to IPv4 addresses and localhost
			if (addr instanceof Inet4Address || addr.isLoopbackAddress()) {
				InetSocketAddress bindToAddress = new InetSocketAddress(addr, config.getCoapPort());
				addEndpoint(new CoapEndpoint(bindToAddress));
	            logger.info("Bound CoAP server to " + addr + " and port " + config.getCoapPort());
			}
		}

    }
}