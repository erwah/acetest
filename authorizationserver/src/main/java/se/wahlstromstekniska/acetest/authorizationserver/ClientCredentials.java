package se.wahlstromstekniska.acetest.authorizationserver;

public class ClientCredentials {

	private String client_id = "";
	private String client_secret = "";
	
	public ClientCredentials(String client_id, String client_secret) {
		super();
		this.client_id = client_id;
		this.client_secret = client_secret;
	}
	
	public String getClient_id() {
		return client_id;
	}
	public void setClient_id(String client_id) {
		this.client_id = client_id;
	}
	public String getClient_secret() {
		return client_secret;
	}
	public void setClient_secret(String client_secret) {
		this.client_secret = client_secret;
	}
}
