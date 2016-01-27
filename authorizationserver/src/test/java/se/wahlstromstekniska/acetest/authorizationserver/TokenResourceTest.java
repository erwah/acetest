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

public class TokenResourceTest {
	public static final String TOKEN = "token";


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
		request.setURI("coap://localhost:"+CoAPAuthorizationServer.COAP_PORT+"/"+TOKEN);

		TokenRequest req = new TokenRequest();
		req.setGrantType("client_credentials");
		req.setAud("tempSensorInLivingRoom");
		req.setClientID("myclient");
		req.setClientSecret("qwerty");

		request.setPayload(req.toJson());
		Response response = request.send().waitForResponse();

		Assert.assertEquals(response.getCode(), ResponseCode.CONTENT);
		
		TestUtils.validateToken(response.getPayload(), "tempSensorInLivingRoom");
	}
	
	@Test
	public void testSuccessDTLS() throws Exception {

		TokenRequest req = new TokenRequest();
		req.setGrantType("client_credentials");
		req.setAud("tempSensorInLivingRoom");
		req.setClientID("myclient");
		req.setClientSecret("qwerty");

		Response response = DTLSRequest.dtlsRequest("coaps://localhost:"+CoAPSAuthorizationServer.COAPS_PORT+"/"+TOKEN, "POST", req.toJson(), MediaTypeRegistry.TEXT_PLAIN);		

		System.out.println(response);
		System.out.println("Time elapsed (ms): " + response.getRTT());
		Assert.assertEquals(response.getCode(), ResponseCode.CONTENT);
	}
	

	@Test
	public void testSuccessClientGeneratedKeys() throws Exception {

		JsonWebKey jwk;
		jwk = EcJwkGenerator.generateJwk(EllipticCurves.P256);
		jwk.setKeyId("testkid");
		
		TokenRequest req = new TokenRequest();
		req.setGrantType("client_credentials");
		req.setAud("tempSensorInLivingRoom");
		req.setClientID("myclient");
		req.setClientSecret("qwerty");
		req.setKey(jwk);

		Response response = DTLSRequest.dtlsRequest("coaps://localhost:"+CoAPSAuthorizationServer.COAPS_PORT+"/"+TOKEN, "POST", req.toJson(), MediaTypeRegistry.TEXT_PLAIN);		

		Assert.assertEquals(ResponseCode.CONTENT, response.getCode());

		TestUtils.validateToken(response.getPayload(), "tempSensorInLivingRoom");
	}
	

	@Test
	public void testWrongClient() throws Exception {
		TokenRequest req = new TokenRequest();
		req.setGrantType("client_credentials");
		req.setAud("tempSensorInLivingRoom");
		req.setClientID("notmyclient");
		req.setClientSecret("qwerty");
		callBadRequestEndpointCall(req.toJson(), "unauthorized_client");
	}	

	@Test
	public void testWrongSecret() throws Exception {
		TokenRequest req = new TokenRequest();
		req.setGrantType("client_credentials");
		req.setAud("tempSensorInLivingRoom");
		req.setClientID("myclient");
		req.setClientSecret("wrongpassword");
		callBadRequestEndpointCall(req.toJson(), "unauthorized_client");
	}	

	@Test
	public void testWrongAud() throws Exception {
		TokenRequest req = new TokenRequest();
		req.setGrantType("client_credentials");
		req.setAud("wrongaud");
		req.setClientID("myclient");
		req.setClientSecret("qwerty");
		callBadRequestEndpointCall(req.toJson(), "unauthorized_client");
	}	

	@Test
	public void testWrongGrant() throws Exception {
		TokenRequest req = new TokenRequest();
		req.setGrantType("notValidGrant");
		req.setAud("tempSensorInLivingRoom");
		req.setClientID("myclient");
		req.setClientSecret("qwerty");
		callBadRequestEndpointCall(req.toJson(), "invalid_grant");
	}	
	
	@Test
	public void testMissingAud() throws Exception {
		TokenRequest req = new TokenRequest();
		req.setGrantType("client_credentials");
		req.setClientID("myclient");
		req.setClientSecret("qwerty");
		callBadRequestEndpointCall(req.toJson(), "invalid_request");
	}	

	@Test
	public void testMissingGrantType() throws Exception {
		TokenRequest req = new TokenRequest();
		req.setAud("tempSensorInLivingRoom");
		req.setClientID("myclient");
		req.setClientSecret("qwerty");
		callBadRequestEndpointCall(req.toJson(), "invalid_request");
	}	

	private void callBadRequestEndpointCall(String payload, String expectedError) throws Exception {

		Response response = DTLSRequest.dtlsRequest("coaps://localhost:"+CoAPSAuthorizationServer.COAPS_PORT+"/"+TOKEN, "POST", payload, MediaTypeRegistry.TEXT_PLAIN);		
		
		Assert.assertEquals(response.getCode(), ResponseCode.BAD_REQUEST);
		
    	// take request and turn it into a TokenRequest object
    	byte[] error = response.getPayload();
    	ErrorResponse errorResp = new ErrorResponse(error);
    	Assert.assertEquals(expectedError, errorResp.getError());
	}
	
}
