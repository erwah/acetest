package se.wahlstromstekniska.acetest.client;

import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Response;

import se.wahlstromstekniska.acetest.authorizationserver.Constants;
import se.wahlstromstekniska.acetest.authorizationserver.DTLSRequest;
import se.wahlstromstekniska.acetest.authorizationserver.ServerConfiguration;
import se.wahlstromstekniska.acetest.authorizationserver.resource.TokenRequest;
import se.wahlstromstekniska.acetest.authorizationserver.resource.TokenResponse;


public class Client {

	private static ServerConfiguration config = ServerConfiguration.getInstance();
	
	public static void main(String[] args) {
		TokenRequest req = new TokenRequest();
		req.setGrantType("client_credentials");
		req.setAud("tempSensorInLivingRoom");
		req.setClientID("myclient");
		req.setClientSecret("qwerty");
		req.setScopes("read write");

		Response response;
		try {
			response = DTLSRequest.dtlsRequest("coaps://localhost:"+config.getCoapsPort()+"/"+Constants.TOKEN_RESOURCE, "POST", req.toPayload(MediaTypeRegistry.APPLICATION_JSON), MediaTypeRegistry.APPLICATION_JSON);

			TokenResponse tokenResponse = new TokenResponse(response.getPayload(), response.getOptions().getContentFormat());
			
			String accessToken = tokenResponse.getAccessToken();
			
			System.out.println(accessToken);
			System.out.println(response);
			System.out.println("Time elapsed (ms): " + response.getRTT());
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}		

	}

}
