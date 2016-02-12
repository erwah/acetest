package se.wahlstromstekniska.acetest.authorizationserver;

import java.util.ArrayList;

import org.jose4j.jwk.EllipticCurveJsonWebKey;

public class ResourceServer {

	public static int TOKEN_FORMAT_JWT = 0;
	public static int TOKEN_FORMAT_CWT = 1;

	public static int TRANSPORT_ENCRYPTION_DTLS_PSK = 0;
	public static int TRANSPORT_ENCRYPTION_DTLS_RPK = 1;
	public static int TRANSPORT_ENCRYPTION_DTLS_CERT = 2;
	public static int TRANSPORT_ENCRYPTION_OSCON = 3;
	
	private String clientId;
	private String clientSecret;
	private String aud;
	private ArrayList<AccessToken> accessTokens = new ArrayList<AccessToken>();
	private ArrayList<String> authorizedClients = new ArrayList<String>();
	private String csp;
	private int tokenformat;
	private String scopes = new String();
	private int transportEncryption = 0; 
	private EllipticCurveJsonWebKey rpk = null; 

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
	
	public AccessToken getResourceServersTokenRepresentation(String token) {
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

	public int getTransportEncryption() {
		return transportEncryption;
	}

	public void setTransportEncryption(int transportEncryption) {
		this.transportEncryption = transportEncryption;
	}

	public EllipticCurveJsonWebKey getRPK() {
		return rpk;
	}

	public void setRPK(EllipticCurveJsonWebKey rpk) {
		this.rpk = rpk;
	}


	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	@Override
	public String toString() {
		return "ResourceServer [clientId=" + clientId + ", clientSecret="
				+ clientSecret + ", aud=" + aud + ", accessTokens="
				+ accessTokens + ", authorizedClients=" + authorizedClients
				+ ", csp=" + csp + ", tokenformat=" + tokenformat + ", scopes="
				+ scopes + ", transportEncryption=" + transportEncryption
				+ ", rpk=" + rpk + "]";
	}
	
	
}
