package se.wahlstromstekniska.acetest.authorizationserver;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;

import org.apache.log4j.Logger;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;

import se.wahlstromstekniska.acetest.authorizationserver.resource.TokenResource;
import se.wahlstromstekniska.acetest.authorizationserver.resource.IntrospectResource;


public class CoAPAuthorizationServer extends CoapServer {

	protected static final int COAP_PORT = NetworkConfig.getStandard().getInt(NetworkConfig.Keys.COAP_PORT);

	final static Logger logger = Logger.getLogger(CoAPAuthorizationServer.class);
	
	@SuppressWarnings("unused")
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
				InetSocketAddress bindToAddress = new InetSocketAddress(addr, COAP_PORT);
				addEndpoint(new CoapEndpoint(bindToAddress));
	            logger.info("Bound CoAP server to " + addr + " and port " + COAP_PORT);
			}
		}

    }
}