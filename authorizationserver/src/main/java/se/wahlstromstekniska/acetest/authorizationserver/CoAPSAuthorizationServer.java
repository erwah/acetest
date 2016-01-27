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
	// allows configuration via Californium.properties
//	protected static final int COAPS_PORT = NetworkConfig.getStandard().getInt(NetworkConfig.Keys.COAP_SECURE_PORT);
	protected static final int COAPS_PORT = 5685;
	
	private static final String TRUST_STORE_PASSWORD = "rootPass";
	private static final String KEY_STORE_PASSWORD = "endPass";
	private static final String KEY_STORE_LOCATION = "../certs/keyStore.jks";
	private static final String TRUST_STORE_LOCATION = "../certs/trustStore.jks";

	final static Logger logger = Logger.getLogger(CoAPAuthorizationServer.class);

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
	    pskStore.setKey("Client_identity", "secretPSK".getBytes());
	    
		InputStream in = null;

		// load the key store
		KeyStore keyStore = KeyStore.getInstance("JKS");
		in = new FileInputStream(KEY_STORE_LOCATION);
		keyStore.load(in, KEY_STORE_PASSWORD.toCharArray());

		// load the trust store
		KeyStore trustStore = KeyStore.getInstance("JKS");
		InputStream inTrust = new FileInputStream(TRUST_STORE_LOCATION);
		trustStore.load(inTrust, TRUST_STORE_PASSWORD.toCharArray());

		// You can load multiple certificates if needed
		Certificate[] trustedCertificates = new Certificate[1];
		trustedCertificates[0] = trustStore.getCertificate("root");


		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(new InetSocketAddress(COAPS_PORT));
		builder.setPskStore(pskStore);
		builder.setIdentity((PrivateKey)keyStore.getKey("server", KEY_STORE_PASSWORD.toCharArray()), keyStore.getCertificateChain("server"), true);
		builder.setTrustStore(trustedCertificates);
		
		
		DTLSConnector connector = new DTLSConnector(builder.build(), null);

    	for (InetAddress addr : EndpointManager.getEndpointManager().getNetworkInterfaces()) {
    		// only binds to IPv4 addresses and localhost
			if (addr instanceof Inet4Address || addr.isLoopbackAddress()) {
				CoapEndpoint endpoint = new CoapEndpoint(connector, new NetworkConfig().getStandard()); 
				addEndpoint(endpoint);
				// TODO: make sure this was placed correctly
				EndpointManager.getEndpointManager().setDefaultSecureEndpoint(endpoint);
	            logger.info("Bound CoAPS server to " + addr + " and port " + COAPS_PORT);
			}
		}
    }


}