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
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;
import org.junit.Assert;

import se.wahlstromstekniska.acetest.authorizationserver.resource.TokenRequest;

public class DTLSRequest {

	public static final String TOKEN = "token";
	
	protected static final int COAPS_PORT = NetworkConfig.getStandard().getInt(NetworkConfig.Keys.COAP_SECURE_PORT);
	
	private static final String TRUST_STORE_PASSWORD = "rootPass";
	private static final String KEY_STORE_PASSWORD = "endPass";
	private static final String KEY_STORE_LOCATION = "../certs/keyStore.jks";
	private static final String TRUST_STORE_LOCATION = "../certs/trustStore.jks";
			
    CoAPSAuthorizationServer server;
    
	private static Endpoint dtlsEndpoint;

	static boolean loop = false;
	static boolean useRaw = true;

	public static Response dtlsRequest(String uri, String method, String payload, int contentFormat) throws Exception {
		boolean usePSK = true;

		Request request = Utils.newRequest(method);
		request.setURI(uri);
		request.setPayload(payload);
		request.getOptions().setContentFormat(contentFormat);

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
		dtlsEndpoint.start();

		// execute request
		request.send(dtlsEndpoint);
		Response response = request.waitForResponse();
		
		return response;
	}

	
}
