package se.wahlstromstekniska.acetest.authorizationserver;

import java.util.ArrayList;

public class ResourceServer {

	public static int TOKEN_FORMAT_JWT = 0;
	public static int TOKEN_FORMAT_CWT = 1;
	
	private String aud;
	private ArrayList<AccessToken> accessTokens = new ArrayList<AccessToken>();
	private ArrayList<String> authorizedClients = new ArrayList<String>();
	private String csp;
	private int tokenformat;
	private String scopes = new String();

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
	
	public AccessToken getResourceTokensTokenRepresentation(String token) {
		for (AccessToken t : accessTokens) {
			if(t.getAccessToken().equals(token)) {
				return t;
			}
		}
		return null;
	}

	public int getTokenFormat() {
		return tokenformat;
	}

	public void setTokenFormat(int tokenformat) {
		this.tokenformat = tokenformat;
	}

	public String getScopes() {
		return scopes;
	}

	public void setScopes(String scopes) {
		this.scopes = scopes;
	}

	@Override
	public String toString() {
		return "ResourceServer [aud=" + aud + ", accessTokens=" + accessTokens
				+ ", authorizedClients=" + authorizedClients + ", csp=" + csp
				+ ", tokenformat=" + tokenformat + ", scopes=" + scopes + "]";
	}
	

}
