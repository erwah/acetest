package se.wahlstromstekniska.acetest.authorizationserver;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.keys.EllipticCurves;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import se.wahlstromstekniska.acetest.authorizationserver.resource.TokenRequest;

public class CBORTokenResourceTest {

	private static ServerConfiguration config = ServerConfiguration.getInstance();

	@Before
	public void startupServer() throws Exception {
		try {
			// DTLS protected CoAP Server
	        CoAPSAuthorizationServer.main(new String[] {});
	        
	        // Unprotected CoAP Server
	        CoAPAuthorizationServer.main(new String[] {});
	        
			System.out.println("OAuth2 AS is started successfully.");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	

	@Test
	public void testSuccessPlaintext() throws Exception {
		Request request = Request.newPost();
		request.setURI("coap://localhost:"+config.getCoapPort()+"/"+Constants.TOKEN_RESOURCE);

		TokenRequest req = new TokenRequest();
		req.setGrantType("client_credentials");
		req.setAud("tempSensorInLivingRoom");
		req.setClientID("myclient");
		req.setClientSecret("qwerty");
		req.setScopes("read write");

		request.getOptions().setContentFormat(MediaTypeRegistry.APPLICATION_CBOR);
		request.setPayload(req.toPayload(MediaTypeRegistry.APPLICATION_CBOR));
		Response response = request.send().waitForResponse();

		Assert.assertEquals(response.getCode(), ResponseCode.CONTENT);
		
		TestUtils.validateToken(response.getPayload(), "tempSensorInLivingRoom", MediaTypeRegistry.APPLICATION_CBOR);
	}

}
