package se.wahlstromstekniska.acetest.authorizationserver;

import org.jose4j.jwk.EllipticCurveJsonWebKey;

public class Client {

	private String client_id = "";
	private String client_secret = "";
	private EllipticCurveJsonWebKey jwk = null;
	
	public Client(String client_id, String client_secret, EllipticCurveJsonWebKey jwk) {
		super();
		this.client_id = client_id;
		this.client_secret = client_secret;
		this.jwk = jwk;
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

	@Override
	public String toString() {
		return "ClientCredentials [client_id=" + client_id + ", client_secret=xxxx]";
	}

	public EllipticCurveJsonWebKey getJwk() {
		return jwk;
	}

	public void setJwk(EllipticCurveJsonWebKey jwk) {
		this.jwk = jwk;
	}
	
}
