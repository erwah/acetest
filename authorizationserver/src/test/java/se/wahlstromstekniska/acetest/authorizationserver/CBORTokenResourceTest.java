package se.wahlstromstekniska.acetest.authorizationserver;

import org.junit.Before;
import org.junit.Test;

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
		/*
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
		*/
	}

}
