package se.wahlstromstekniska.acetest.resourceserver;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.logging.Level;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.ScandiumLogger;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;

public class DtlsRPKServer extends CoapServer {

	private static ResourceServerConfiguration config = ResourceServerConfiguration.getInstance();

	static {
		ScandiumLogger.initialize();
		ScandiumLogger.setLevel(Level.INFO);
	}

    public DtlsRPKServer() throws Exception {
	    
        add(new TemperatureResource());
	    
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(new InetSocketAddress(config.getCoapsPort()));
		builder.setClientAuthenticationRequired(true);
		// use the global in memory psk key store from the global config object
		builder.setTrustedPublicKeysStore(config.getPublicKeyStorage());
		
		PublicKey publicKey = config.getRpk().getPublicKey();
		PrivateKey privateKey = config.getRpk().getPrivateKey();
		
		builder.setIdentity(privateKey, publicKey);
		
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
