package se.wahlstromstekniska.acetest.authorizationserver;

import java.net.SocketException;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
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
	public static final String INTROSPECT = "introspect";
	
	@SuppressWarnings("unused")
	private static ServerConfiguration config = ServerConfiguration.getInstance();
	
	private int serverPort = AuthorizationServer.COAP_PORT;
			
    AuthorizationServer server;

	@Before
	public void startupServer() throws Exception {
		try {
			server = new AuthorizationServer();
	        server.addEndpoints();
	        server.start();
		} catch (SocketException e) {
			e.printStackTrace();
		}
	}
	
	@After
	public void shutdownServer() {
		try {
			server.stop();
			server.destroy();
			server = null;
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
		
		TokenRequest req = new TokenRequest();
		req.setGrantType("client_credentials");
		req.setAud("tempSensorInLivingRoom");
		req.setClientID("myclient");
		req.setClientSecret("qwerty");
		req.setKey(jwk);

		Request createRequest = Request.newPost();
		createRequest.setURI("coap://localhost:"+serverPort+"/token");
		createRequest.setPayload(req.toJson());
		Response createResponse = createRequest.send().waitForResponse();
	
		Assert.assertEquals(ResponseCode.CONTENT, createResponse.getCode());
		
		TokenResponse tokenResponse = new TokenResponse(createResponse.getPayload());
		
		// see of token is valid 
		Request request = Request.newPost();
		request.setURI("coap://localhost:"+serverPort+"/"+INTROSPECT);
		
		IntrospectRequest introspectionReq = new IntrospectRequest();
		introspectionReq.setToken(tokenResponse.getAccessToken());
		introspectionReq.setClientID("myclient");
		introspectionReq.setClientSecret("qwerty");
		
		request.setPayload(introspectionReq.toJson());
		Response response = request.send().waitForResponse();

		Assert.assertEquals(response.getCode(), ResponseCode.CONTENT);

		IntrospectResponse introspectResponse = new IntrospectResponse(response.getPayload());
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
		
		Request request = Request.newPost();
		request.setURI("coap://localhost:"+serverPort+"/"+INTROSPECT);

		request.setPayload(req.toJson());
		Response response = request.send().waitForResponse();

		Assert.assertEquals(response.getCode(), ResponseCode.CONTENT);

		IntrospectResponse introspectResponse = new IntrospectResponse(response.getPayload());
		Assert.assertFalse(introspectResponse.isActive());
	}	

	private void callBadRequestEndpointCall(String payload, String expectedError) throws Exception {
		Request request = Request.newPost();
		request.setURI("coap://localhost:"+serverPort+"/"+INTROSPECT);
		request.setPayload(payload);
		Response response = request.send().waitForResponse();

		Assert.assertEquals(response.getCode(), ResponseCode.BAD_REQUEST);
		
    	// take request and turn it into a TokenRequest object
    	byte[] error = response.getPayload();
    	ErrorResponse errorResp = new ErrorResponse(error);
    	Assert.assertEquals(expectedError, errorResp.getError());
	}
}
