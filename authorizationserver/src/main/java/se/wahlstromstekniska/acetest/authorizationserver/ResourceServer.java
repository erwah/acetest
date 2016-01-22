package se.wahlstromstekniska.acetest.authorizationserver;

import java.util.ArrayList;

public class ResourceServer {

	private String aud;
	private ArrayList<Object> accessTokens = new ArrayList<Object>();
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
	
	public void addAccessToken(Object token) {
		accessTokens.add(token);
	}
	
	public void removeAccessToken(Object token) {
		accessTokens.remove(token);
	}
	
	public boolean validateToken(Object token) {
		if(accessTokens.contains(token)) {
			// TODO: validate validity time, signature....
			return true;
		}
		else {
			return false;
		}
	}

	@Override
	public String toString() {
		return "ResourceServer [aud=" + aud + ", accessTokens=" + accessTokens
				+ ", authorizedClients=" + authorizedClients + ", csp=" + csp
				+ "]";
	}
	

}
