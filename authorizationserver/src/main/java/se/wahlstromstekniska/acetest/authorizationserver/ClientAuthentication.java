package se.wahlstromstekniska.acetest.authorizationserver;

import org.apache.log4j.Logger;

public class ClientAuthentication {
	
	final static Logger logger = Logger.getLogger(ClientAuthentication.class);

	private static ServerConfiguration config = ServerConfiguration.getInstance();

	public ClientAuthentication() {
	}

	/**
	 * DO NOT USE THIS METHOD IN PRODUCTION! It's just a POC.
	 * TODO: Create a real authentication flow.
	 * @param clientId
	 * @param clientSecret
	 * @return
	 */
	public boolean authenticate(String clientId, String clientSecret) {
		// validate input
		// TODO: add more validation.
		if(clientId == null 
				|| clientId.trim().length() == 0 
				|| clientSecret == null 
				|| clientSecret.trim().length() == 0) {
			return false;
		}
		else {
			boolean ok = false;
			
			Client client = config.getClient(clientId);
			if(client != null) {
				if(client.getClient_id().equals(clientId) && client.getClient_secret().equals(clientSecret)) {
					logger.debug("Client '" + clientId + "' authenticated successfully.");
					ok = true;
				}
			}

			ResourceServer rs = config.getResourceServerWithClientId(clientId);
			if(rs != null) {
				if(rs.getClientId().equals(clientId) && rs.getClientSecret().equals(clientSecret)) {
					logger.debug("Resource Server '" + clientId + "' authenticated successfully.");
					ok = true;
				}
			}

			return ok;
		}
	}
	
}
