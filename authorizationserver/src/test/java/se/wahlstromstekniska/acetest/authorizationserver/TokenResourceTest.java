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

		request.getOptions().setContentFormat(MediaTypeRegistry.APPLICATION_JSON);
		request.setPayload(req.toPayload(MediaTypeRegistry.APPLICATION_JSON));
		Response response = request.send().waitForResponse();

		Assert.assertEquals(response.getCode(), ResponseCode.CONTENT);
		
		TestUtils.validateToken(response.getPayload(), "tempSensorInLivingRoom", MediaTypeRegistry.APPLICATION_JSON);
	}
	
	@Test
	public void testSuccessDTLS() throws Exception {

		TokenRequest req = new TokenRequest();
		req.setGrantType("client_credentials");
		req.setAud("tempSensorInLivingRoom");
		req.setClientID("myclient");
		req.setClientSecret("qwerty");
		req.setScopes("read write");

		Response response = DTLSRequest.dtlsRequest("coaps://localhost:"+config.getCoapsPort()+"/"+Constants.TOKEN_RESOURCE, "POST", req.toPayload(MediaTypeRegistry.APPLICATION_JSON), MediaTypeRegistry.APPLICATION_JSON);		

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
		req.setScopes("read write");
		req.setKey(jwk);

		Response response = DTLSRequest.dtlsRequest("coaps://localhost:"+config.getCoapsPort()+"/"+Constants.TOKEN_RESOURCE, "POST", req.toPayload(MediaTypeRegistry.APPLICATION_JSON), MediaTypeRegistry.APPLICATION_JSON);		

		Assert.assertEquals(ResponseCode.CONTENT, response.getCode());

		TestUtils.validateToken(response.getPayload(), "tempSensorInLivingRoom", MediaTypeRegistry.APPLICATION_JSON);
	}
	

	@Test
	public void testScopes() throws Exception {

		JsonWebKey jwk;
		jwk = EcJwkGenerator.generateJwk(EllipticCurves.P256);
		jwk.setKeyId("testkid");
		
		TokenRequest req = new TokenRequest();
		req.setGrantType("client_credentials");
		req.setAud("tempSensorInLivingRoom");
		req.setClientID("myclient");
		req.setClientSecret("qwerty");
		req.setScopes("read write");
		req.setKey(jwk);

		Response response = DTLSRequest.dtlsRequest("coaps://localhost:"+config.getCoapsPort()+"/"+Constants.TOKEN_RESOURCE, "POST", req.toPayload(MediaTypeRegistry.APPLICATION_JSON), MediaTypeRegistry.APPLICATION_JSON);		

		Assert.assertEquals(ResponseCode.CONTENT, response.getCode());

		TestUtils.validateToken(response.getPayload(), "tempSensorInLivingRoom", MediaTypeRegistry.APPLICATION_JSON);
	}
	

	@Test
	public void testWrongScopes() throws Exception {
		TokenRequest req = new TokenRequest();
		req.setGrantType("client_credentials");
		req.setAud("tempSensorInLivingRoom");
		req.setClientID("myclient");
		req.setClientSecret("qwerty");
		req.setScopes("wrongscopes");
		callBadRequestEndpointCall(req.toPayload(MediaTypeRegistry.APPLICATION_JSON), "invalid_scope", MediaTypeRegistry.APPLICATION_JSON);
	}	
	

	@Test
	public void testWrongContentTypePlain() throws Exception {
		TokenRequest req = new TokenRequest();
		req.setAud("tempSensorInLivingRoom");
		req.setClientID("myclient");
		req.setClientSecret("qwerty");
		req.setScopes("read write");
		callBadRequestEndpointCall(req.toPayload(MediaTypeRegistry.APPLICATION_JSON), "invalid_request", MediaTypeRegistry.TEXT_PLAIN);
	}
		

	@Test
	public void testWrongClient() throws Exception {
		TokenRequest req = new TokenRequest();
		req.setGrantType("client_credentials");
		req.setAud("tempSensorInLivingRoom");
		req.setClientID("notmyclient");
		req.setClientSecret("qwerty");
		callBadRequestEndpointCall(req.toPayload(MediaTypeRegistry.APPLICATION_JSON), "unauthorized_client", MediaTypeRegistry.APPLICATION_JSON);
	}	

	@Test
	public void testWrongSecret() throws Exception {
		TokenRequest req = new TokenRequest();
		req.setGrantType("client_credentials");
		req.setAud("tempSensorInLivingRoom");
		req.setClientID("myclient");
		req.setClientSecret("wrongpassword");
		callBadRequestEndpointCall(req.toPayload(MediaTypeRegistry.APPLICATION_JSON), "unauthorized_client", MediaTypeRegistry.APPLICATION_JSON);
	}	

	@Test
	public void testWrongAud() throws Exception {
		TokenRequest req = new TokenRequest();
		req.setGrantType("client_credentials");
		req.setAud("wrongaud");
		req.setClientID("myclient");
		req.setClientSecret("qwerty");
		callBadRequestEndpointCall(req.toPayload(MediaTypeRegistry.APPLICATION_JSON), "unauthorized_client", MediaTypeRegistry.APPLICATION_JSON);
	}	

	@Test
	public void testWrongGrant() throws Exception {
		TokenRequest req = new TokenRequest();
		req.setGrantType("notValidGrant");
		req.setAud("tempSensorInLivingRoom");
		req.setClientID("myclient");
		req.setClientSecret("qwerty");
		callBadRequestEndpointCall(req.toPayload(MediaTypeRegistry.APPLICATION_JSON), "invalid_grant", MediaTypeRegistry.APPLICATION_JSON);
	}	
	
	@Test
	public void testMissingAud() throws Exception {
		TokenRequest req = new TokenRequest();
		req.setGrantType("client_credentials");
		req.setClientID("myclient");
		req.setClientSecret("qwerty");
		callBadRequestEndpointCall(req.toPayload(MediaTypeRegistry.APPLICATION_JSON), "invalid_request", MediaTypeRegistry.APPLICATION_JSON);
	}	

	@Test
	public void testMissingGrantType() throws Exception {
		TokenRequest req = new TokenRequest();
		req.setAud("tempSensorInLivingRoom");
		req.setClientID("myclient");
		req.setClientSecret("qwerty");
		callBadRequestEndpointCall(req.toPayload(MediaTypeRegistry.APPLICATION_JSON), "invalid_request", MediaTypeRegistry.APPLICATION_JSON);
	}	

	
	private void callBadRequestEndpointCall(byte[] payload, String expectedError, int contentType) throws Exception {

		Response response = DTLSRequest.dtlsRequest("coaps://localhost:"+config.getCoapsPort()+"/"+Constants.TOKEN_RESOURCE, "POST", payload, contentType);
		
		Assert.assertEquals(response.getCode(), ResponseCode.BAD_REQUEST);
		
    	// take request and turn it into a TokenRequest object
    	byte[] error = response.getPayload();
    	ErrorResponse errorResp = new ErrorResponse(error, MediaTypeRegistry.APPLICATION_JSON);
    	Assert.assertEquals(expectedError, errorResp.getError());
	}
	
}
