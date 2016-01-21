package se.wahlstromstekniska.acetest.authorizationserver;

import java.net.SocketException;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import se.wahlstromstekniska.acetest.authorizationserver.AuthorizationServer;
import se.wahlstromstekniska.acetest.authorizationserver.ClientAuthentication;
import se.wahlstromstekniska.acetest.authorizationserver.ClientCredentials;
import se.wahlstromstekniska.acetest.authorizationserver.Constants;
import se.wahlstromstekniska.acetest.authorizationserver.ManagedResourceServers;
import se.wahlstromstekniska.acetest.authorizationserver.ResourceServer;

public class AuthorizationServerTest {
	public static final String TOKEN = "token";
	
	private static ManagedResourceServers managedResourceServers = ManagedResourceServers.getInstance();
	private static ClientAuthentication auth = ClientAuthentication.getInstance();
	
	public static final String VALID_POST = "{"
     + "  \"grant_type\" : \"client_credentials\","
     + "  \"aud\" : \"tempSensorInLivingRoom\","
     + "  \"client_id\" : \"myclient\","
     + "  \"client_secret\" : \"qwerty\""
   	 + "}";

	public static final String UNAUTHORIZED_USER_POST = "{"
		     + "  \"grant_type\" : \"client_credentials\","
		     + "  \"aud\" : \"tempSensorInLivingRoom\","
		     + "  \"client_id\" : \"notmyclient\","
		     + "  \"client_secret\" : \"qwerty\""
		   	 + "}";

	public static final String UNAUTHORIZED_SECRET_POST = "{"
		     + "  \"grant_type\" : \"client_credentials\","
		     + "  \"aud\" : \"tempSensorInLivingRoom\","
		     + "  \"client_id\" : \"myclient\","
		     + "  \"client_secret\" : \"wrongpw\""
		   	 + "}";

	public static final String MISSING_AUD_POST = "{"
		     + "  \"grant_type\" : \"client_credentials\","
		     + "  \"client_id\" : \"myclient\","
		     + "  \"client_secret\" : \"qwerty\""
		   	 + "}";

	public static final String WRONG_AUD_POST = "{"
		     + "  \"grant_type\" : \"client_credentials\","
		     + "  \"aud\" : \"wrongAud\","
		     + "  \"client_id\" : \"myclient\","
		     + "  \"client_secret\" : \"qwerty\""
		   	 + "}";

	public static final String MISSING_GRANT_TYPE_POST = "{"
		     + "  \"aud\" : \"tempSensorInLivingRoom\","
		     + "  \"client_id\" : \"myclient\","
		     + "  \"client_secret\" : \"qwerty\""
		   	 + "}";

	public static final String WRONG_GRANT_TYPE_POST = "{"
		     + "  \"grant_type\" : \"wrongGrantType\","
		     + "  \"aud\" : \"tempSensorInLivingRoom\","
		     + "  \"client_id\" : \"myclient\","
		     + "  \"client_secret\" : \"qwerty\""
		   	 + "}";

	private int serverPort = AuthorizationServer.COAP_PORT;
			
    AuthorizationServer server;

	@Before
	public void startupServer() throws Exception {
		System.out.println("\nStarting AuthorizationServer.");
		try {
			server = new AuthorizationServer();
	        server.addEndpoints();
	        server.start();
	        
            // add a new RS to test against
            // TODO: move the pre-registered sensors to a configuration file instead.
            ResourceServer tempSensorInLivingRoom = new ResourceServer("tempSensorInLivingRoom");
            tempSensorInLivingRoom.addAuthorizedClient("myclient");
            tempSensorInLivingRoom.setCsp(Constants.cspDTLS);
            
        	managedResourceServers.addResourceServer(tempSensorInLivingRoom);
	        
            auth.addClient(new ClientCredentials("myclient", "qwerty"));

		} catch (SocketException e) {
			System.out.println("Failed to startup AuthorizationServer.");
			e.printStackTrace();
		}
	}
	
	@After
	public void shutdownServer() {
		try {
			server.stop();
			server.destroy();
			server = null;
			
			managedResourceServers.removeResourceServer("tempSensorInLivingRoom");
			auth.deleteClient("myclient");
		} catch (Exception e) {
			System.out.println("Failed to shutdown AuthorizationServer.");
			e.printStackTrace();
		}
	}
	
	@Test
	public void testSuccess() throws Exception {
		Request request = Request.newPost();
		request.setURI("coap://localhost:"+serverPort+"/"+TOKEN);
		request.setPayload(VALID_POST);
		Response response = request.send().waitForResponse();

		Assert.assertEquals(response.getCode(), ResponseCode.CONTENT);
		Assert.assertNotNull("Client received no response", response);

		// TODO: Assert.assertEquals(expectations[i], response.getPayloadString());
		// TODO: assert token!
	}
	

	@Test
	public void testWrongUser() throws Exception {
		callBadRequestEndpointCall(UNAUTHORIZED_USER_POST);
	}	

	@Test
	public void testWrongSecret() throws Exception {
		callBadRequestEndpointCall(UNAUTHORIZED_SECRET_POST);
	}	

	@Test
	public void testMissingAud() throws Exception {
		callBadRequestEndpointCall(MISSING_AUD_POST);
	}	

	@Test
	public void testMissingGrantType() throws Exception {
		callBadRequestEndpointCall(MISSING_GRANT_TYPE_POST);
	}	

	@Test
	public void testWrongAud() throws Exception {
		callBadRequestEndpointCall(WRONG_AUD_POST);
	}	

	@Test
	public void testWrongGrant() throws Exception {
		callBadRequestEndpointCall(WRONG_GRANT_TYPE_POST);
	}	

	private void callBadRequestEndpointCall(String payload) throws Exception {
		Request request = Request.newPost();
		request.setURI("coap://localhost:"+serverPort+"/"+TOKEN);
		request.setPayload(payload);
		Response response = request.send().waitForResponse();

		Assert.assertEquals(response.getCode(), ResponseCode.BAD_REQUEST);
	}

}
