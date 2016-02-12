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

import se.wahlstromstekniska.acetest.authorizationserver.resource.IntrospectRequest;
import se.wahlstromstekniska.acetest.authorizationserver.resource.IntrospectResponse;
import se.wahlstromstekniska.acetest.authorizationserver.resource.TokenRequest;
import se.wahlstromstekniska.acetest.authorizationserver.resource.TokenResponse;

public class IntrospectResourceTest {

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
	public void testSuccess() throws Exception {
		// first create a token
		JsonWebKey jwk;
		jwk = EcJwkGenerator.generateJwk(EllipticCurves.P256);
		jwk.setKeyId("testkid");
		
		TokenRequest createReq = new TokenRequest();
		createReq.setGrantType("client_credentials");
		createReq.setAud(config.getResourceServers().get(0).getAud());
		createReq.setClientID(config.getClients().get(0).getClient_id());
		createReq.setClientSecret(config.getClients().get(0).getClient_secret());
		createReq.setScopes(config.getResourceServers().get(0).getScopes());
		createReq.setKey(jwk);


		Response createResponse = DTLSUtils.dtlsPSKRequest("coaps://localhost:"+config.getCoapsPort()+"/"+Constants.TOKEN_RESOURCE, "POST", createReq.toPayload(MediaTypeRegistry.APPLICATION_JSON), MediaTypeRegistry.APPLICATION_JSON, config.getPskIdentity(), config.getPskKey().getBytes());		
		Assert.assertEquals(ResponseCode.CONTENT, createResponse.getCode());
		
		TokenResponse tokenResponse = new TokenResponse(createResponse.getPayload(), MediaTypeRegistry.APPLICATION_JSON);
		
		// see of token is valid 
		IntrospectRequest introspectionReq = new IntrospectRequest();
		introspectionReq.setToken(tokenResponse.getAccessToken());
		introspectionReq.setClientID(config.getClients().get(0).getClient_id());
		introspectionReq.setClientSecret(config.getClients().get(0).getClient_secret());
		
		Response introspectionResponse = DTLSUtils.dtlsPSKRequest("coaps://localhost:"+config.getCoapsPort()+"/"+Constants.INSTROSPECTION_RESOURCE, "POST", introspectionReq.toPayload(MediaTypeRegistry.APPLICATION_JSON), MediaTypeRegistry.APPLICATION_JSON, config.getPskIdentity(), config.getPskKey().getBytes());	

		Assert.assertEquals(introspectionResponse.getCode(), ResponseCode.CONTENT);

		IntrospectResponse introspectResponse = new IntrospectResponse(introspectionResponse.getPayload(), MediaTypeRegistry.APPLICATION_JSON);
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
		createReq.setAud(config.getResourceServers().get(0).getAud());
		createReq.setClientID(config.getClients().get(0).getClient_id());
		createReq.setClientSecret(config.getClients().get(0).getClient_secret());
		createReq.setScopes(config.getResourceServers().get(0).getScopes());
		createReq.setKey(jwk);
		
		Request request = Request.newPost();
		request.setURI("coap://localhost:"+config.getCoapPort()+"/"+Constants.TOKEN_RESOURCE);
		request.setPayload(createReq.toPayload(MediaTypeRegistry.APPLICATION_JSON));
		request.getOptions().setContentFormat(MediaTypeRegistry.APPLICATION_JSON);

		Response createResponse = request.send().waitForResponse();

		Assert.assertEquals(ResponseCode.CONTENT, createResponse.getCode());
		
		TokenResponse tokenResponse = new TokenResponse(createResponse.getPayload(), MediaTypeRegistry.APPLICATION_JSON);
		
		// see of token is valid 
		IntrospectRequest introspectionReq = new IntrospectRequest();
		introspectionReq.setToken(tokenResponse.getAccessToken());
		introspectionReq.setClientID(config.getClients().get(0).getClient_id());
		introspectionReq.setClientSecret(config.getClients().get(0).getClient_secret());
		
		Request introspectionRequest = Request.newPost();
		introspectionRequest.setURI("coap://localhost:"+config.getCoapPort()+"/"+Constants.INSTROSPECTION_RESOURCE);
		introspectionRequest.setPayload(introspectionReq.toPayload(MediaTypeRegistry.APPLICATION_JSON));
		introspectionRequest.getOptions().setContentFormat(MediaTypeRegistry.APPLICATION_JSON);

		Response introspectionResponse = introspectionRequest.send().waitForResponse();

		Assert.assertEquals(introspectionResponse.getCode(), ResponseCode.CONTENT);
		
		IntrospectResponse introspectResponse = new IntrospectResponse(introspectionResponse.getPayload(), MediaTypeRegistry.APPLICATION_JSON);
		Assert.assertTrue(introspectResponse.isActive());
	}
		

	@Test
	public void testWrongClient() throws Exception {
		IntrospectRequest req = new IntrospectRequest();
		req.setToken("loremipsum");
		req.setClientID("notmyclient");
		req.setClientSecret("qwerty");
		callBadRequestEndpointCall(req.toPayload(MediaTypeRegistry.APPLICATION_JSON), "unauthorized_client", MediaTypeRegistry.APPLICATION_JSON);
	}	

	@Test
	public void testWrongSecret() throws Exception {
		IntrospectRequest req = new IntrospectRequest();
		req.setToken("loremipsum");
		req.setClientID("myclient");
		req.setClientSecret("wrongpassword");
		callBadRequestEndpointCall(req.toPayload(MediaTypeRegistry.APPLICATION_JSON), "unauthorized_client", MediaTypeRegistry.APPLICATION_JSON);
	}	

	@Test
	public void invalidToken() throws Exception {
		IntrospectRequest req = new IntrospectRequest();
		req.setToken("loremipsum");
		
		req.setClientID(config.getClients().get(0).getClient_id());
		req.setClientSecret(config.getClients().get(0).getClient_secret());
		
		Response response = DTLSUtils.dtlsPSKRequest("coaps://localhost:"+config.getCoapsPort()+"/"+Constants.INSTROSPECTION_RESOURCE, "POST", req.toPayload(MediaTypeRegistry.APPLICATION_JSON), MediaTypeRegistry.APPLICATION_JSON, config.getPskIdentity(), config.getPskKey().getBytes());	

		Assert.assertEquals(response.getCode(), ResponseCode.CONTENT);

		IntrospectResponse introspectResponse = new IntrospectResponse(response.getPayload(), MediaTypeRegistry.APPLICATION_JSON);
		Assert.assertFalse(introspectResponse.isActive());
	}	

	private void callBadRequestEndpointCall(byte[] payload, String expectedError, int contentFormat) throws Exception {
		Response response = DTLSUtils.dtlsPSKRequest("coaps://localhost:"+config.getCoapsPort()+"/"+Constants.INSTROSPECTION_RESOURCE, "POST", payload, contentFormat, config.getPskIdentity(), config.getPskKey().getBytes());

		Assert.assertEquals(response.getCode(), ResponseCode.BAD_REQUEST);
		
    	// take request and turn it into a TokenRequest object
    	byte[] error = response.getPayload();
    	ErrorResponse errorResp = new ErrorResponse(error, MediaTypeRegistry.APPLICATION_JSON);
    	Assert.assertEquals(expectedError, errorResp.getError());
	}
}
