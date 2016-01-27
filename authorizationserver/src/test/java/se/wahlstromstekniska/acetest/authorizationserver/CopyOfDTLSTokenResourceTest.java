package se.wahlstromstekniska.acetest.authorizationserver;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;

import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;
import org.junit.Before;
import org.junit.Test;

import se.wahlstromstekniska.acetest.authorizationserver.resource.TokenRequest;

public class CopyOfDTLSTokenResourceTest {
	public static final String TOKEN = "token";
	
	private static ServerConfiguration config = ServerConfiguration.getInstance();
	
	// exit codes for runtime errors
	private static final int ERR_REQUEST_FAILED  = 5;
	private static final int ERR_RESPONSE_FAILED = 6;

	protected static final int COAPS_PORT = NetworkConfig.getStandard().getInt(NetworkConfig.Keys.COAP_SECURE_PORT);
	
	private static final String TRUST_STORE_PASSWORD = "rootPass";
	private static final String KEY_STORE_PASSWORD = "endPass";
	private static final String KEY_STORE_LOCATION = "../certs/keyStore.jks";
	private static final String TRUST_STORE_LOCATION = "../certs/trustStore.jks";


	private int serverPort = CoAPSAuthorizationServer.COAPS_PORT;
			
    CoAPSAuthorizationServer server;
    
	private static Endpoint dtlsEndpoint;

	static boolean loop = false;
	static boolean useRaw = true;


	@Before
	public void startupServer() throws Exception {
		try {
	        CoAPSAuthorizationServer.main(new String[] {});
			System.out.println("OAuth2 AS is started successfully.");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	@Test
	public void testSuccess() throws Exception {

		// TODO: hardcoded for now.
		boolean usePSK = true;
		String method = "POST";
		
		TokenRequest req = new TokenRequest();
		req.setGrantType("client_credentials");
		req.setAud("tempSensorInLivingRoom");
		req.setClientID("myclient");
		req.setClientSecret("qwerty");

		Request request = newRequest(method);
		request.setURI("coaps://localhost:"+serverPort+"/"+TOKEN);
		request.setPayload(req.toJson());
		request.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);

		// load trust store
		KeyStore trustStore = KeyStore.getInstance("JKS");
		InputStream inTrust = new FileInputStream(TRUST_STORE_LOCATION);
		trustStore.load(inTrust, TRUST_STORE_PASSWORD.toCharArray());
		// load multiple certificates if needed
		Certificate[] trustedCertificates = new Certificate[1];
		trustedCertificates[0] = trustStore.getCertificate("root");

		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(new InetSocketAddress(0));

		builder.setTrustStore(trustedCertificates);
		if (usePSK) {
			builder.setPskStore(new StaticPskStore("Client_identity", "secretPSK".getBytes()));
			builder.setSupportedCipherSuites(new CipherSuite[] {CipherSuite.TLS_PSK_WITH_AES_128_CCM_8});
		} else {
			KeyStore keyStore = KeyStore.getInstance("JKS");
			InputStream in = new FileInputStream(KEY_STORE_LOCATION);
			keyStore.load(in, KEY_STORE_PASSWORD.toCharArray());
			builder.setIdentity((PrivateKey)keyStore.getKey("client", KEY_STORE_PASSWORD.toCharArray()), keyStore.getCertificateChain("client"), useRaw);
		}

		DTLSConnector dtlsconnector = new DTLSConnector(builder.build(), null);

		
		NetworkConfig nc = NetworkConfig.createStandardWithFile(new File("../eriksnetworks.txt"));
		
		dtlsEndpoint = new CoapEndpoint(dtlsconnector, nc);
		
//		dtlsEndpoint = new CoapEndpoint(dtlsconnector, NetworkConfig.getStandard());
		dtlsEndpoint.start();
//		EndpointManager.getEndpointManager().setDefaultSecureEndpoint(dtlsEndpoint);

		// execute request
		try {
			request.send(dtlsEndpoint);
//			request.send();

			// loop for receiving multiple responses
			do {
	
				// receive response
				Response response = null;
				try {
					response = request.waitForResponse();
				} catch (InterruptedException e) {
					System.err.println("Failed to receive response: " + e.getMessage());
					System.exit(ERR_RESPONSE_FAILED);
				}
	
				// output response
	
				if (response != null) {
	
					System.out.println(response);
					System.out.println("Time elapsed (ms): " + response.getRTT());
	
					// check of response contains resources
					if (response.getOptions().isContentFormat(MediaTypeRegistry.APPLICATION_LINK_FORMAT)) {
	
						String linkFormat = response.getPayloadString();
	
						// output discovered resources
						System.out.println("\nDiscovered resources:");
						System.out.println(linkFormat);
	
					} else {
						// check if link format was expected by client
						if (method.equals("DISCOVER")) {
							System.out.println("Server error: Link format not specified");
						}
					}
	
				} else {
					// no response received	
					System.err.println("Request timed out");
					break;
				}
	
			} while (loop);
			
		} catch (Exception e) {
			System.err.println("Failed to execute request: " + e.getMessage());
			System.exit(ERR_REQUEST_FAILED);
		}

		
				/*
		Request request = Request.newPost();


		Response response = request.send().waitForResponse();

		Assert.assertEquals(response.getCode(), ResponseCode.CONTENT);
		
		*/
	}


	/*
	 * Instantiates a new request based on a string describing a method.
	 * 
	 * @return A new request object, or null if method not recognized
	 */
	private static Request newRequest(String method) {
		if (method.equals("GET")) {
			return Request.newGet();
		} else if (method.equals("POST")) {
			return Request.newPost();
		} else if (method.equals("PUT")) {
			return Request.newPut();
		} else if (method.equals("DELETE")) {
			return Request.newDelete();
		} else if (method.equals("DISCOVER")) {
			return Request.newGet();
		} else if (method.equals("OBSERVE")) {
			Request request = Request.newGet();
			request.setObserve();
			loop = true;
			return request;
		} else {
			System.err.println("Unknown method: " + method);
			return null;
		}
	}
}
