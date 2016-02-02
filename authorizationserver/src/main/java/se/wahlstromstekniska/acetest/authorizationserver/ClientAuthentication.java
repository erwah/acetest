package se.wahlstromstekniska.acetest.authorizationserver;

import org.apache.log4j.Logger;

public class ClientAuthentication {
	
	final static Logger logger = Logger.getLogger(ClientAuthentication.class);

	private static ServerConfiguration config = ServerConfiguration.getInstance();

	public ClientAuthentication() {
	}

	/**
	 * DO NOT USE THIS METHOD IN PRODUCTION! It's just a POC.
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
			
			ClientCredentials client = config.getClient(clientId);
			if(client != null) {
				if(client.getClient_id().equals(clientId) && client.getClient_secret().equals(clientSecret)) {
					logger.debug("Client '" + clientId + "' authenticated successfully.");
					ok = true;
				}
			}
			
			return ok;
		}
	}
	
}
