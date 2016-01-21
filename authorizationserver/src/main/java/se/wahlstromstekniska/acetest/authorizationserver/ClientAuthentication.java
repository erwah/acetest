package se.wahlstromstekniska.acetest.authorizationserver;

import java.util.ArrayList;

public class ClientAuthentication {

	private static ClientAuthentication instance = null;

	ArrayList<ClientCredentials> clients = new ArrayList<ClientCredentials>();
	
	protected ClientAuthentication() {
		
	}
	
	public static ClientAuthentication getInstance() {
		if(instance == null) {
			instance = new ClientAuthentication();
		}
		return instance;
	}

	
	public boolean authenticate(String client_id, String client_secret) {
		if(client_id == null 
				|| client_id.trim().length() == 0 
				|| client_secret == null 
				|| client_secret.trim().length() == 0) {
			return false;
		}
		else {
			boolean ok = false;
			
			for (ClientCredentials client : clients) {
				if(client.getClient_id().equals(client_id) && client.getClient_secret().equals(client_secret)) {
					System.out.println("Client authentication successful. NOTE: Hardcoded creds!");
					ok = true;
				}
			}
			
			return ok;
		}
	}
	
	public void addClient(ClientCredentials client) {
		clients.add(client);
	}
	
	public void deleteClient(String client_id) {
		ClientCredentials clientToDelete = null;
		
		for (ClientCredentials client : clients) {
			if(client.getClient_id().equals(client_id)) {
				clientToDelete = client;
			}
		}
		
		clients.remove(clientToDelete);
	}
	
}
