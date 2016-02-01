package se.wahlstromstekniska.acetest.authorizationserver.resource;

import java.nio.charset.StandardCharsets;

import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKey.OutputControlLevel;
import org.jose4j.lang.JoseException;
import org.json.JSONException;
import org.json.JSONObject;

import se.wahlstromstekniska.acetest.authorizationserver.Constants;
import se.wahlstromstekniska.acetest.authorizationserver.exception.RequestException;

/**
 * Parses a TokenReques, JSON or CBOR and expose getters for all values.
 * @author erikw
 *
 */
public class TokenRequest {
	
	private int contentFormat = MediaTypeRegistry.APPLICATION_JSON;
	private String grant_type = "";
	private String aud = "";
	private String client_id = "";
	private String client_secret = "";
	private String scopes = "";
	private JsonWebKey key = null;
	
	public TokenRequest(byte[] payload, int contentFormat) throws Exception {
		
		if(contentFormat == MediaTypeRegistry.APPLICATION_JSON) {
			String json = new String(payload, StandardCharsets.UTF_8);
			JSONObject obj = new JSONObject(json);
			setGrantType(obj.getString("grant_type"));
			setAud(obj.getString("aud"));
			setClientID(obj.getString("client_id"));
			setClientSecret(obj.getString("client_secret"));
			setScopes(obj.getString("scopes"));
			
			// either client or AS can generate keys
			if(obj.has("key")) {
				// client generated keys and sent public key
				JsonWebKey jwk = JsonWebKey.Factory.newJwk(obj.getJSONObject("key").toString());
				setKey(jwk);
			}
		}
		else if(contentFormat == MediaTypeRegistry.APPLICATION_CBOR) {
			throw new Exception("CBOR not implemented yet");
		}
		else {
			throw new Exception("Unknown content format.");
		}
	}

	public TokenRequest() {
	}

	public boolean validateRequest() throws RequestException {
		boolean valid = false;
		
		if(aud != null 
				&& aud.trim().length() != 0 
				&& grant_type != null 
				&& grant_type.trim().length() != 0
				&& client_id != null 
				&& client_id.trim().length() != 0
				&& client_secret != null 
				&& client_secret.trim().length() != 0) {

			// throw special exception if the grant type is not valid.
			if(!grant_type.equals(Constants.grantTypeClientCreds)) {
				throw new RequestException("No valid grant_type.", RequestException.MISSING_GRANT);
			}

			valid = true;
		}
		return valid;
	}
	
	public String getGrant_type() {
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

	public String getClient_id() {
		return client_id;
	}

	public void setClientID(String client_id) {
		this.client_id = client_id;
	}

	public String getClient_secret() {
		return client_secret;
	}

	public void setClientSecret(String client_secret) {
		this.client_secret = client_secret;
	}
	
	public JsonWebKey getRawKey() {
		return key;
	}

	public String getKey() {
		return key.toJson(OutputControlLevel.PUBLIC_ONLY);
	}
	
	public void setKey(JsonWebKey key) {
		this.key = key;
	}
	
	public String getScopes() {
		return scopes;
	}

	public void setScopes(String scopes) {
		this.scopes = scopes;
	}
	
	public int getContentFormat() {
		return contentFormat;
	}

	public void setContentFormat(int contentFormat) {
		this.contentFormat = contentFormat;
	}

	
	public String toJson() {
		
		String json = "{"
	     + "  \"grant_type\" : \"" + grant_type + "\","
	     + "  \"aud\" : \"" + aud + "\",";
		
		if(key != null) {
		     json += "  \"key\" : " + key.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY) + ",";
		}
		
		json += "  \"client_id\" : \"" + client_id + "\","
	     + "  \"client_secret\" : \"" + client_secret + "\","
	     + "  \"scopes\" : \"" + scopes + "\""
	   	 + "}";

		return json;
	}

	@Override
	public String toString() {
		return "TokenRequest [contentFormat=" + contentFormat + ", grant_type="
				+ grant_type + ", aud=" + aud + ", client_id=" + client_id
				+ ", client_secret=" + client_secret + ", scopes=" + scopes
				+ ", key (public only)=" + key.toJson(OutputControlLevel.PUBLIC_ONLY) + "]";
	}

}
