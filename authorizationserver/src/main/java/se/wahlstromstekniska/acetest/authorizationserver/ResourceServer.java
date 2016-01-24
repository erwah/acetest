package se.wahlstromstekniska.acetest.authorizationserver;

import java.util.ArrayList;

public class ResourceServer {

	private String aud;
	private ArrayList<AccessToken> accessTokens = new ArrayList<AccessToken>();
	private ArrayList<String> authorizedClients = new ArrayList<String>();
	private String csp;


	public ResourceServer(String aud) {
		this.aud = aud;
	}
	
	public String getAud() {
		return this.aud;
	}
	public void setAud(String aud) {
		this.aud = aud;
	}
	
	public void addAuthorizedClient(String client) {
		authorizedClients.add(client);
	}

	public void removeAuthorizedClient(String client) {
		authorizedClients.remove(client);
	}


	public boolean isClientAuthorized(String client) {
		if(authorizedClients.contains(client)) {
			return true;
		}
		else {
			return false;
		}
	}
	
	public String getCsp() {
		return csp;
	}

	public void setCsp(String csp) {
		this.csp = csp;
	}
	
	public void addAccessToken(AccessToken token) {
		accessTokens.add(token);
	}
	
	public void removeAccessToken(AccessToken token) {
		accessTokens.remove(token);
	}
	
	public boolean validateToken(String token) {
		boolean validity = false;
		for (AccessToken t : accessTokens) {
			if(t.getAccessToken().equals(token)) {
				validity = true;
			}
		}
		return validity;
	}

	@Override
	public String toString() {
		return "ResourceServer [aud=" + aud + ", accessTokens=" + accessTokens
				+ ", authorizedClients=" + authorizedClients + ", csp=" + csp
				+ "]";
	}
	

}
