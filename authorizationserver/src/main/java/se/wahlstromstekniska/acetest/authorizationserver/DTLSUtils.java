package se.wahlstromstekniska.acetest.authorizationserver;

import java.net.InetSocketAddress;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;

public class DTLSUtils {
			
    CoAPSAuthorizationServer server;
    
	private static Endpoint dtlsEndpoint;

	static boolean loop = false;
	static boolean useRaw = true;

	
	public static Response dtlsPSKRequest(String uri, String method, byte[] payload, int contentFormat, String pskIdentity, byte[] pskKey) throws Exception {

		Request request = Utils.newRequest(method);
		request.setURI(uri);
		request.setPayload(payload);
		request.getOptions().setContentFormat(contentFormat);

		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(new InetSocketAddress(0));
		builder.setPskStore(new StaticPskStore(pskIdentity, pskKey));
		builder.setSupportedCipherSuites(new CipherSuite[] {CipherSuite.TLS_PSK_WITH_AES_128_CCM_8});

		DTLSConnector dtlsconnector = new DTLSConnector(builder.build(), null);

		NetworkConfig nc = NetworkConfig.getStandard().setInt("COAP_SECURE_PORT", 15686);

		dtlsEndpoint = new CoapEndpoint(dtlsconnector, nc);
		dtlsEndpoint.start();

		// execute request
		request.send(dtlsEndpoint);
		Response response = request.waitForResponse();
		
		return response;
	}
	
	public static Response dtlsRPKRequest(String uri, String method, byte[] payload, int contentFormat, JsonWebKey popKey, ArrayList<PublicKey> trustedPublicKeys) throws Exception {

		Request request = Utils.newRequest(method);
		request.setURI(uri);
		request.setPayload(payload);
		request.getOptions().setContentFormat(contentFormat);

		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(new InetSocketAddress(0));

		PublicKey publicKey = null;
		PrivateKey privateKey = null;
		
		if(popKey.getKeyType().equalsIgnoreCase("ec")) {
			EllipticCurveJsonWebKey ecPopKey = (EllipticCurveJsonWebKey) popKey;
			privateKey = ecPopKey.getPrivateKey();
			publicKey = ecPopKey.getPublicKey();			
		}
		else if(popKey.getKeyType().equalsIgnoreCase("rsa")) {
			RsaJsonWebKey rsaPopKey = (RsaJsonWebKey) popKey;
			privateKey = rsaPopKey.getPrivateKey();
			publicKey = rsaPopKey.getPublicKey();			
		}
		
		// use the POP key as the requests identity
		builder.setIdentity(privateKey, publicKey);

		// authenticate the remote part using PSK
		builder.setTrustedPublicKeysStore(trustedPublicKeys);

		DTLSConnector dtlsconnector = new DTLSConnector(builder.build(), null);

		NetworkConfig nc = NetworkConfig.getStandard().setInt("COAP_SECURE_PORT", 15685);

		dtlsEndpoint = new CoapEndpoint(dtlsconnector, nc);
		dtlsEndpoint.start();

		// execute request
		request.send(dtlsEndpoint);
		Response response = request.waitForResponse();
		
		return response;
	}		
}
