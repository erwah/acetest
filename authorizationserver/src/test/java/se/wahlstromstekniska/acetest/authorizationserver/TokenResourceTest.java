package se.wahlstromstekniska.acetest.authorizationserver;

import java.math.BigInteger;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.OctJwkGenerator;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.keys.EllipticCurves;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import se.wahlstromstekniska.acetest.authorizationserver.resource.TokenRequest;
import se.wahlstromstekniska.acetest.authorizationserver.resource.TokenResponse;

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

		TokenResponse tokenResponse = new TokenResponse(response.getPayload(), MediaTypeRegistry.APPLICATION_JSON);

		TestUtils.validateToken(tokenResponse.getAccessToken().getBytes(), "tempSensorInLivingRoom", MediaTypeRegistry.APPLICATION_JSON);
	}
	
	@Test
	public void testSuccessDTLS() throws Exception {

		TokenRequest req = new TokenRequest();
		req.setGrantType("client_credentials");
		req.setAud("tempSensorInLivingRoom");
		req.setClientID("myclient");
		req.setClientSecret("qwerty");
		req.setScopes("read write");

		Response response = DTLSUtils.dtlsPSKRequest("coaps://localhost:"+config.getCoapsPort()+"/"+Constants.TOKEN_RESOURCE, "POST", req.toPayload(MediaTypeRegistry.APPLICATION_JSON), MediaTypeRegistry.APPLICATION_JSON, config.getPskIdentity(), config.getPskKey().getBytes());		

		System.out.println(response);
		System.out.println("Time elapsed (ms): " + response.getRTT());
		Assert.assertEquals(response.getCode(), ResponseCode.CONTENT);
	}
	
	@Test
	public void testSuccessClientGeneratedECKeys() throws Exception {

		JsonWebKey popKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
		popKey.setKeyId("testkid");
		
		TokenRequest req = new TokenRequest();
		req.setGrantType("client_credentials");
		req.setAud("tempSensorInLivingRoom");
		req.setClientID("myclient");
		req.setClientSecret("qwerty");
		req.setScopes("read write");
		req.setKey(popKey);

		Response response = DTLSUtils.dtlsPSKRequest("coaps://localhost:"+config.getCoapsPort()+"/"+Constants.TOKEN_RESOURCE, "POST", req.toPayload(MediaTypeRegistry.APPLICATION_JSON), MediaTypeRegistry.APPLICATION_JSON, config.getPskIdentity(), config.getPskKey().getBytes());		

		Assert.assertEquals(ResponseCode.CONTENT, response.getCode());
		
		TokenResponse tokenResponse = new TokenResponse(response.getPayload(), MediaTypeRegistry.APPLICATION_JSON);

		TestUtils.validateToken(tokenResponse.getAccessToken().getBytes(), "tempSensorInLivingRoom", MediaTypeRegistry.APPLICATION_JSON);
	}

	@Test
	public void testSuccessClientGeneratedRSAKeys() throws Exception {

		JsonWebKey popKey = RsaJwkGenerator.generateJwk(2048);
		popKey.setKeyId("testkid");
		
		TokenRequest req = new TokenRequest();
		req.setGrantType("client_credentials");
		req.setAud("tempSensorInLivingRoom");
		req.setClientID("myclient");
		req.setClientSecret("qwerty");
		req.setScopes("read write");
		req.setKey(popKey);

		Response response = DTLSUtils.dtlsPSKRequest("coaps://localhost:"+config.getCoapsPort()+"/"+Constants.TOKEN_RESOURCE, "POST", req.toPayload(MediaTypeRegistry.APPLICATION_JSON), MediaTypeRegistry.APPLICATION_JSON, config.getPskIdentity(), config.getPskKey().getBytes());		

		Assert.assertEquals(ResponseCode.CONTENT, response.getCode());
		
		TokenResponse tokenResponse = new TokenResponse(response.getPayload(), MediaTypeRegistry.APPLICATION_JSON);

		TestUtils.validateToken(tokenResponse.getAccessToken().getBytes(), "tempSensorInLivingRoom", MediaTypeRegistry.APPLICATION_JSON);
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

		Response response = DTLSUtils.dtlsPSKRequest("coaps://localhost:"+config.getCoapsPort()+"/"+Constants.TOKEN_RESOURCE, "POST", req.toPayload(MediaTypeRegistry.APPLICATION_JSON), MediaTypeRegistry.APPLICATION_JSON, config.getPskIdentity(), config.getPskKey().getBytes());		

		TokenResponse tokenResponse = new TokenResponse(response.getPayload(), MediaTypeRegistry.APPLICATION_JSON);

		TestUtils.validateToken(tokenResponse.getAccessToken().getBytes(), "tempSensorInLivingRoom", MediaTypeRegistry.APPLICATION_JSON);
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

		Response response = DTLSUtils.dtlsPSKRequest("coaps://localhost:"+config.getCoapsPort()+"/"+Constants.TOKEN_RESOURCE, "POST", payload, contentType, config.getPskIdentity(), config.getPskKey().getBytes());
		
		Assert.assertEquals(response.getCode(), ResponseCode.BAD_REQUEST);
		
    	// take request and turn it into a TokenRequest object
    	byte[] error = response.getPayload();
    	ErrorResponse errorResp = new ErrorResponse(error, MediaTypeRegistry.APPLICATION_JSON);
    	Assert.assertEquals(expectedError, errorResp.getError());
	}
	
}
