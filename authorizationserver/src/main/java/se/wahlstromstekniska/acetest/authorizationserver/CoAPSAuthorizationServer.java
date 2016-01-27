package se.wahlstromstekniska.acetest.authorizationserver;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
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

	final static Logger logger = Logger.getLogger(CoAPAuthorizationServer.class);

	private static final String TRUST_STORE_PASSWORD = "rootPass";
	private static final String KEY_STORE_PASSWORD = "endPass";
	private static final String KEY_STORE_LOCATION = "../certs/keyStore.jks";
	private static final String TRUST_STORE_LOCATION = "../certs/trustStore.jks";

    static CoAPSAuthorizationServer server = null;

	static {
		ScandiumLogger.initialize();
		ScandiumLogger.setLevel(Level.FINE);
	}


	public static void main(String[] args) {
        try {
            logger.info("Starting server.");
            server = new CoAPSAuthorizationServer();
        	server.start();
        } catch (Exception e) {
            System.err.println("Failed to initialize server: " + e.getMessage());
        }
	}
	
    public CoAPSAuthorizationServer() throws Exception {
	    
        add(new TokenResource());
        add(new IntrospectResource());

	    InMemoryPskStore pskStore = new InMemoryPskStore();
	    pskStore.setKey("Client_identity", config.getPsk().getBytes());
	    
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
		builder.setPskStore(pskStore);
		builder.setIdentity((PrivateKey)keyStore.getKey("server", config.getKeyStorePassword().toCharArray()), keyStore.getCertificateChain("server"), true);
		builder.setTrustStore(trustedCertificates);
		
		
		DTLSConnector connector = new DTLSConnector(builder.build(), null);

    	for (InetAddress addr : EndpointManager.getEndpointManager().getNetworkInterfaces()) {
    		// only binds to IPv4 addresses and localhost
			if (addr instanceof Inet4Address || addr.isLoopbackAddress()) {
				CoapEndpoint endpoint = new CoapEndpoint(connector, new NetworkConfig().getStandard()); 
				addEndpoint(endpoint);
				// TODO: make sure this was placed correctly
				EndpointManager.getEndpointManager().setDefaultSecureEndpoint(endpoint);
	            logger.info("Bound CoAPS server to " + addr + " and port " + config.getCoapsPort());
			}
		}
    }


}