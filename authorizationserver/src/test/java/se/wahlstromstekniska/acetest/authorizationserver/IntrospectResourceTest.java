package se.wahlstromstekniska.acetest.authorizationserver;

import java.net.SocketException;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.keys.EllipticCurves;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import se.wahlstromstekniska.acetest.authorizationserver.resource.IntrospectRequest;
import se.wahlstromstekniska.acetest.authorizationserver.resource.IntrospectResponse;
import se.wahlstromstekniska.acetest.authorizationserver.resource.TokenRequest;
import se.wahlstromstekniska.acetest.authorizationserver.resource.TokenResponse;

public class IntrospectResourceTest {
	public static final String TOKEN = "token";
	public static final String INTROSPECT = "introspect";

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
	public void testSuccess() throws Exception {
		// first create a token
		JsonWebKey jwk;
		jwk = EcJwkGenerator.generateJwk(EllipticCurves.P256);
		jwk.setKeyId("testkid");
		
		TokenRequest createReq = new TokenRequest();
		createReq.setGrantType("client_credentials");
		createReq.setAud("tempSensorInLivingRoom");
		createReq.setClientID("myclient");
		createReq.setClientSecret("qwerty");
		createReq.setKey(jwk);

		Response createResponse = DTLSRequest.dtlsRequest("coaps://localhost:"+CoAPSAuthorizationServer.COAPS_PORT+"/"+TOKEN, "POST", createReq.toJson(), MediaTypeRegistry.TEXT_PLAIN);		
		Assert.assertEquals(ResponseCode.CONTENT, createResponse.getCode());
		
		TokenResponse tokenResponse = new TokenResponse(createResponse.getPayload());
		
		// see of token is valid 
		IntrospectRequest introspectionReq = new IntrospectRequest();
		introspectionReq.setToken(tokenResponse.getAccessToken());
		introspectionReq.setClientID("myclient");
		introspectionReq.setClientSecret("qwerty");
		
		Response introspectionResponse = DTLSRequest.dtlsRequest("coaps://localhost:"+CoAPSAuthorizationServer.COAPS_PORT+"/"+INTROSPECT, "POST", introspectionReq.toJson(), MediaTypeRegistry.TEXT_PLAIN);	

		Assert.assertEquals(introspectionResponse.getCode(), ResponseCode.CONTENT);

		IntrospectResponse introspectResponse = new IntrospectResponse(introspectionResponse.getPayload());
		Assert.assertTrue(introspectResponse.isActive());
	}
	

	@Test
	public void testSuccessPlaintext() throws Exception {

		// first create a token
		JsonWebKey jwk;
		jwk = EcJwkGenerator.generateJwk(EllipticCurves.P256);
		jwk.setKeyId("testkid");
		
		TokenRequest createReq = new TokenRequest();
		createReq.setGrantType("client_credentials");
		createReq.setAud("tempSensorInLivingRoom");
		createReq.setClientID("myclient");
		createReq.setClientSecret("qwerty");
		createReq.setKey(jwk);
		
		Request request = Request.newPost();
		request.setURI("coap://localhost:"+CoAPAuthorizationServer.COAP_PORT+"/"+TOKEN);
		request.setPayload(createReq.toJson());
		Response createResponse = request.send().waitForResponse();

		Assert.assertEquals(ResponseCode.CONTENT, createResponse.getCode());
		
		TokenResponse tokenResponse = new TokenResponse(createResponse.getPayload());
		
		// see of token is valid 
		IntrospectRequest introspectionReq = new IntrospectRequest();
		introspectionReq.setToken(tokenResponse.getAccessToken());
		introspectionReq.setClientID("myclient");
		introspectionReq.setClientSecret("qwerty");
		
		Request introspectionRequest = Request.newPost();
		introspectionRequest.setURI("coap://localhost:"+CoAPAuthorizationServer.COAP_PORT+"/"+INTROSPECT);
		introspectionRequest.setPayload(introspectionReq.toJson());
		Response introspectionResponse = introspectionRequest.send().waitForResponse();

		Assert.assertEquals(introspectionResponse.getCode(), ResponseCode.CONTENT);
		
		IntrospectResponse introspectResponse = new IntrospectResponse(introspectionResponse.getPayload());
		Assert.assertTrue(introspectResponse.isActive());
		
	}
		

	@Test
	public void testWrongClient() throws Exception {
		IntrospectRequest req = new IntrospectRequest();
		req.setToken("loremipsum");
		req.setClientID("notmyclient");
		req.setClientSecret("qwerty");
		callBadRequestEndpointCall(req.toJson(), "unauthorized_client");
	}	

	@Test
	public void testWrongSecret() throws Exception {
		IntrospectRequest req = new IntrospectRequest();
		req.setToken("loremipsum");
		req.setClientID("myclient");
		req.setClientSecret("wrongpassword");
		callBadRequestEndpointCall(req.toJson(), "unauthorized_client");
	}	

	@Test
	public void invalidToken() throws Exception {
		IntrospectRequest req = new IntrospectRequest();
		req.setToken("loremipsum");
		req.setClientID("myclient");
		req.setClientSecret("qwerty");
		
		Response response = DTLSRequest.dtlsRequest("coaps://localhost:"+CoAPSAuthorizationServer.COAPS_PORT+"/"+INTROSPECT, "POST", req.toJson(), MediaTypeRegistry.TEXT_PLAIN);	

		Assert.assertEquals(response.getCode(), ResponseCode.CONTENT);

		IntrospectResponse introspectResponse = new IntrospectResponse(response.getPayload());
		Assert.assertFalse(introspectResponse.isActive());
	}	

	private void callBadRequestEndpointCall(String payload, String expectedError) throws Exception {
		Response response = DTLSRequest.dtlsRequest("coaps://localhost:"+CoAPSAuthorizationServer.COAPS_PORT+"/"+INTROSPECT, "POST", payload, MediaTypeRegistry.TEXT_PLAIN);

		Assert.assertEquals(response.getCode(), ResponseCode.BAD_REQUEST);
		
    	// take request and turn it into a TokenRequest object
    	byte[] error = response.getPayload();
    	ErrorResponse errorResp = new ErrorResponse(error);
    	Assert.assertEquals(expectedError, errorResp.getError());
	}
}
