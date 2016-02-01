package se.wahlstromstekniska.acetest.authorizationserver.resource;

import java.nio.charset.StandardCharsets;

import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.lang.JoseException;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * Parses a Introspect request, JSON or CBOR and expose getters for all values.
 * @author erikw
 *
 */
public class IntrospectRequest {
	
	private String client_id = "";
	private String client_secret = "";
	private String token = "";
	private String resource_id = "";
	
	public IntrospectRequest(byte[] payload, int contentFormat) throws Exception {
		
		if(contentFormat == MediaTypeRegistry.APPLICATION_JSON) {
			String json = new String(payload, StandardCharsets.UTF_8);
			JSONObject obj = new JSONObject(json);
			setClientID(obj.getString("client_id"));
			setClientSecret(obj.getString("client_secret"));
			setToken(obj.getString("token"));
			
			// either client or AS can generate keys
			if(obj.has("resource_id")) {
				setResourceId(obj.getString("resource_id"));
			}
		}
		else if(contentFormat == MediaTypeRegistry.APPLICATION_CBOR) {
			throw new Exception("CBOR not implemented yet");
		}
		else {
			throw new Exception("Unknown content format.");
		}		
		
	}

	public IntrospectRequest() {
		
	}
	
	public boolean validateRequest() {
		boolean valid = false;
		if(token.trim().length() != 0) {
			valid = true;
		}
		return valid;
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

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}

	public String getResourceId() {
		return resource_id;
	}

	public void setResourceId(String resource_id) {
		this.resource_id = resource_id;
	}

	
	@Override
	public String toString() {
		return "IntrospectRequest [client_id=" + client_id + ", client_secret="
				+ client_secret + ", token=" + token + ", resource_id="
				+ resource_id + "]";
	}
	
	public String toJson() {
		
		String json = "{"
	     + "  \"client_id\" : \"" + client_id + "\","
	     + "  \"client_secret\" : \"" + client_secret + "\","
		 + "  \"token\" : \"" + token + "\","
	     + "  \"resource_id\" : \"" + resource_id + "\""
	   	 + "}";

		return json;
	}	

}
