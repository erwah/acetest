package se.wahlstromstekniska.acetest.authorizationserver;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.logging.Level;

import org.apache.log4j.Logger;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.ScandiumLogger;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.pskstore.InMemoryPskStore;

import se.wahlstromstekniska.acetest.authorizationserver.resource.IntrospectResource;
import se.wahlstromstekniska.acetest.authorizationserver.resource.TokenResource;


public class CoAPSAuthorizationServer extends CoapServer {

	private static ServerConfiguration config = ServerConfiguration.getInstance();

	final static Logger logger = Logger.getLogger(CoAPSAuthorizationServer.class);

    static CoAPSAuthorizationServer server = null;

	static {
		ScandiumLogger.initialize();
		ScandiumLogger.setLevel(Level.INFO);
	}


	public static void main(String[] args) {
        try {
            server = new CoAPSAuthorizationServer();
        	server.start();
        } catch (Exception e) {
            logger.error("Failed to initialize server.", e);
        }
	}
	
    public CoAPSAuthorizationServer() throws Exception {
	    
        add(new TokenResource());
        add(new IntrospectResource());

	    InMemoryPskStore pskStore = new InMemoryPskStore();
	    pskStore.setKey(config.getPskIdentity(), config.getPskKey().getBytes());

		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(new InetSocketAddress(config.getCoapsPort()));
		builder.setClientAuthenticationRequired(true);
		builder.setPskStore(pskStore);
		
		DTLSConnector connector = new DTLSConnector(builder.build(), null);

    	for (InetAddress addr : EndpointManager.getEndpointManager().getNetworkInterfaces()) {
    		// only binds to IPv4 addresses and localhost
			if (addr instanceof Inet4Address || addr.isLoopbackAddress()) {
				@SuppressWarnings("static-access")
				CoapEndpoint endpoint = new CoapEndpoint(connector, new NetworkConfig().getStandard()); 
				addEndpoint(endpoint);
				EndpointManager.getEndpointManager().setDefaultSecureEndpoint(endpoint);
			}
		}
    }

}