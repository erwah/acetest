package se.wahlstromstekniska.acetest.authorizationserver;

import java.nio.charset.StandardCharsets;

import org.json.JSONObject;

/**
 * Parses a TokenReques, JSON or CBOR and expose getters for all values.
 * @author erikw
 *
 */
public class TokenRequest {
	
	private String grant_type = "";
	private String aud = "";
	private String client_id = "";
	private String client_secret = "";
	
	public TokenRequest(byte[] payload) {
		// is it JSON or CBOR?
		// TODO: do the real check and add CBOR support
		boolean isJSON = true;
		
		if(isJSON) {
			String json = new String(payload, StandardCharsets.UTF_8);
			JSONObject obj = new JSONObject(json);
			setGrantType(obj.getString("grant_type"));
			setAud(obj.getString("aud"));
			setClientID(obj.getString("client_id"));
			setClientSecret(obj.getString("client_secret"));
		}
	}

	public boolean validateRequest() {
		boolean valid = false;
		if(aud != null 
				&& aud.trim().length() != 0 
				&& grant_type != null 
				&& grant_type.equals(Constants.grantTypeClientCreds)
				&& client_id != null 
				&& client_id.trim().length() != 0
				&& client_secret != null 
				&& client_secret.trim().length() != 0) {
			valid = true;
		}
		return valid;
	}
	
	public String getGrantType() {
		return grant_type;
	}

	public void setGrantType(String grant_type) {
		this.grant_type = grant_type;
	}

	public String getAud() {
		return aud;
	}

	public void setAud(String aud) {
		this.aud = aud;
	}

	public String getClientID() {
		return client_id;
	}

	public void setClientID(String client_id) {
		this.client_id = client_id;
	}

	public String getClientSecret() {
		return client_secret;
	}

	public void setClientSecret(String client_secret) {
		this.client_secret = client_secret;
	}

	@Override
	public String toString() {
		return "TokenRequest [grant_type=" + grant_type + ", aud=" + aud
				+ ", client_id=" + client_id + ", client_secret=XXXXXXX]";
	}
	
	
}
