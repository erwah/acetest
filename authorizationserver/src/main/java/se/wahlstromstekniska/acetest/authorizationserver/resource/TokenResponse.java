package se.wahlstromstekniska.acetest.authorizationserver.resource;

import java.nio.charset.StandardCharsets;

import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.jose4j.lang.JoseException;
import org.json.JSONException;
import org.json.JSONObject;

import se.wahlstromstekniska.acetest.authorizationserver.AccessToken;
import se.wahlstromstekniska.acetest.authorizationserver.Constants;

public class TokenResponse {

	private String accessToken = "";
	private String tokenType = "";
	private String csp = "";
	private String key = "";
	
	public TokenResponse(byte[] payload, int contentFormat) throws Exception {
		if(contentFormat == MediaTypeRegistry.APPLICATION_JSON) {
			String json = new String(payload, StandardCharsets.UTF_8);
			JSONObject obj = new JSONObject(json);
			setAccessToken(obj.getString("access_token"));
			setTokenType(obj.getString("token_type"));
			setCsp(obj.getString("csp"));
			if(obj.has("key")) {
				setKey(obj.getString("key"));
			}
		}
		else {
			throw new Exception("Not implemented yet");
		}		
	}
	
	public TokenResponse(AccessToken accessToken, String tokenType, String csp, String key) {
		this.accessToken = accessToken.getAccessToken();
		this.tokenType = tokenType;
		this.csp = csp;
		this.key = key;
	}

	public byte[] toPayload(int contentFormat) {

		if(contentFormat == MediaTypeRegistry.APPLICATION_JSON) {
			String json = "{ "
					+ "\n\t\"access_token\" : \"" + accessToken + "\"," 
					+ "\n\t\"token_type\" : \"" + Constants.tokenTypePOP + "\","
					+ "\n\t\"csp\" : \"" + csp+ "\"";
			
			if(key != null) {
				json += ",\n\t\"key\" : \"" + key + "\"";
			}
			
			json += "\n}";
			
			return json.getBytes();
		}
		else {
			return "not implemented yet".getBytes();
		}
	}
	
	public String getAccessToken() {
		return accessToken;
	}
	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}
	public String getTokenType() {
		return tokenType;
	}
	public void setTokenType(String tokenType) {
		this.tokenType = tokenType;
	}
	public String getCsp() {
		return csp;
	}
	public void setCsp(String csp) {
		this.csp = csp;
	}
	public String getKey() {
		return key;
	}
	public void setKey(String key) {
		this.key = key;
	}
}
