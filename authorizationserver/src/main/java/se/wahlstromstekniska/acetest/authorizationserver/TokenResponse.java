package se.wahlstromstekniska.acetest.authorizationserver;

public class TokenResponse {

	private String accessToken = "";
	private String tokenType = "";
	private String csp = "";
	private String key = "";
	
	public TokenResponse() {
		
	}

	public TokenResponse(String accessToken, String tokenType, String csp, String key) {
		this.accessToken = accessToken;
		this.tokenType = tokenType;
		this.csp = csp;
		this.key = key;
	}

	public String getJSON() {

		String json = "{ "
				+ "\n\t\"access_token\" : \"" + accessToken + "\"," 
				+ "\n\t\"token_type\" : \"" + Constants.tokenTypePOP + "\","
				+ "\n\t\"csp\" : \"" + csp+ "\"";
		
		if(key != null) {
			json += ",\n\t\"key\" : \"" + key + "\"";
		}
		
		json += "\n}";
		
		return json;
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
