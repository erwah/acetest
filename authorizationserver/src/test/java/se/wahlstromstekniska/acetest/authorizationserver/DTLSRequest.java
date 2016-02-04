package se.wahlstromstekniska.acetest.authorizationserver;

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;

public class DTLSRequest {
			
	private static ServerConfiguration config = ServerConfiguration.getInstance();

    CoAPSAuthorizationServer server;
    
	private static Endpoint dtlsEndpoint;

	static boolean loop = false;
	static boolean useRaw = true;

	
	public static Response dtlsRequest(String uri, String method, byte[] payload, int contentFormat) throws Exception {
		boolean usePSK = true;

		Request request = Utils.newRequest(method);
		request.setURI(uri);
		request.setPayload(payload);
		request.getOptions().setContentFormat(contentFormat);

		// load trust store
		KeyStore trustStore = KeyStore.getInstance("JKS");
		InputStream inTrust = new FileInputStream(config.getTrustStoreLocation());
		trustStore.load(inTrust, config.getTrustStorePassword().toCharArray());
		// load multiple certificates if needed
		Certificate[] trustedCertificates = new Certificate[1];
		trustedCertificates[0] = trustStore.getCertificate("root");

		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(new InetSocketAddress(0));

		builder.setTrustStore(trustedCertificates);
		if (usePSK) {
			builder.setPskStore(new StaticPskStore("Client_identity", config.getPsk().getBytes()));
			builder.setSupportedCipherSuites(new CipherSuite[] {CipherSuite.TLS_PSK_WITH_AES_128_CCM_8});
		} else {
			KeyStore keyStore = KeyStore.getInstance("JKS");
			InputStream in = new FileInputStream(config.getKeyStoreLocation());
			keyStore.load(in, config.getKeyStorePassword().toCharArray());
			builder.setIdentity((PrivateKey)keyStore.getKey("client", config.getKeyStorePassword().toCharArray()), keyStore.getCertificateChain("client"), useRaw);
		}

		DTLSConnector dtlsconnector = new DTLSConnector(builder.build(), null);

		NetworkConfig nc = NetworkConfig.getStandard().setInt("COAP_SECURE_PORT", 15684);

		dtlsEndpoint = new CoapEndpoint(dtlsconnector, nc);
		dtlsEndpoint.start();

		// execute request
		request.send(dtlsEndpoint);
		Response response = request.waitForResponse();
		
		return response;
	}
	
	public static Response dtlsRequest(String uri, String method, byte[] payload, int contentFormat, String pskIdentity, byte[] pskKey) throws Exception {
		boolean usePSK = true;

		Request request = Utils.newRequest(method);
		request.setURI(uri);
		request.setPayload(payload);
		request.getOptions().setContentFormat(contentFormat);

		// load trust store
		KeyStore trustStore = KeyStore.getInstance("JKS");
		InputStream inTrust = new FileInputStream(config.getTrustStoreLocation());
		trustStore.load(inTrust, config.getTrustStorePassword().toCharArray());
		// load multiple certificates if needed
		Certificate[] trustedCertificates = new Certificate[1];
		trustedCertificates[0] = trustStore.getCertificate("root");

		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(new InetSocketAddress(0));

		builder.setTrustStore(trustedCertificates);
		if (usePSK) {
			builder.setPskStore(new StaticPskStore(pskIdentity, pskKey));
			builder.setSupportedCipherSuites(new CipherSuite[] {CipherSuite.TLS_PSK_WITH_AES_128_CCM_8});
		} else {
			KeyStore keyStore = KeyStore.getInstance("JKS");
			InputStream in = new FileInputStream(config.getKeyStoreLocation());
			keyStore.load(in, config.getKeyStorePassword().toCharArray());
			builder.setIdentity((PrivateKey)keyStore.getKey("client", config.getKeyStorePassword().toCharArray()), keyStore.getCertificateChain("client"), useRaw);
		}

		DTLSConnector dtlsconnector = new DTLSConnector(builder.build(), null);

		NetworkConfig nc = NetworkConfig.getStandard().setInt("COAP_SECURE_PORT", 15684);

		dtlsEndpoint = new CoapEndpoint(dtlsconnector, nc);
		dtlsEndpoint.start();

		// execute request
		request.send(dtlsEndpoint);
		Response response = request.waitForResponse();
		
		return response;
	}	
	
}
