package se.wahlstromstekniska.acetest.resourceserver;

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.logging.Level;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.ScandiumLogger;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;

public class DtlsPSKServer extends CoapServer {

	private static ResourceServerConfiguration config = ResourceServerConfiguration.getInstance();

	static {
		ScandiumLogger.initialize();
		ScandiumLogger.setLevel(Level.INFO);
	}

    public DtlsPSKServer() throws Exception {
	    
        add(new TemperatureResource());
	    
		InputStream in = null;

		// load the key store
		KeyStore keyStore = KeyStore.getInstance("JKS");
		in = new FileInputStream(config.getKeyStoreLocation());
		keyStore.load(in, config.getKeyStorePassword().toCharArray());

		// load the trust store
		KeyStore trustStore = KeyStore.getInstance("JKS");
		InputStream inTrust = new FileInputStream(config.getTrustStoreLocation());
		trustStore.load(inTrust, config.getTrustStorePassword().toCharArray());
		
		// You can load multiple certificates if needed
		Certificate[] trustedCertificates = new Certificate[1];
		trustedCertificates[0] = trustStore.getCertificate("root");


		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(new InetSocketAddress(config.getCoapsPort()));
		builder.setClientAuthenticationRequired(true);
		builder.setIdentity((PrivateKey)keyStore.getKey("server", config.getKeyStorePassword().toCharArray()), keyStore.getCertificateChain("server"), true);
		builder.setTrustStore(trustedCertificates);

		// use the global in memory psk key store thats populated using the access tokens from the global config object
		builder.setPskStore(config.getPskStorage());
		
		DTLSConnector connector = new DTLSConnector(builder.build(), null);

    	for (InetAddress addr : EndpointManager.getEndpointManager().getNetworkInterfaces()) {
    		// only binds to IPv4 addresses and localhost
			if (addr instanceof Inet4Address || addr.isLoopbackAddress()) {
				@SuppressWarnings("static-access")
				CoapEndpoint endpoint = new CoapEndpoint(connector, new NetworkConfig().getStandard()); 
				addEndpoint(endpoint);
				// TODO: make sure this was placed correctly
				EndpointManager.getEndpointManager().setDefaultSecureEndpoint(endpoint);
			}
		}
		
	}

}
