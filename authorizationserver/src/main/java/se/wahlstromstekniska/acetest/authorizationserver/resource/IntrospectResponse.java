package se.wahlstromstekniska.acetest.authorizationserver.resource;

import java.nio.charset.StandardCharsets;

import org.jose4j.lang.JoseException;
import org.json.JSONException;
import org.json.JSONObject;


/**
 * Parses a Introspect request, JSON or CBOR and expose getters for all values.
 * @author erikw
 *
 */
public class IntrospectResponse {
	
	private boolean active = false;
	private String scope  = "";
	private String client_id = "";
	private String username = "";
	private String token_type = "";
	private long exp = 0;
	private long iat = 0;
	private long nbf = 0;
	private String sub = "";
	private String aud = "";
	private String iss = "";
	private String cti = "";
	
	
	public IntrospectResponse(boolean active) {
		this.active = active;
	}

	public IntrospectResponse(byte[] payload) throws JSONException, JoseException {
		// is it JSON or CBOR?
		// TODO: do the real check and add CBOR support
		boolean isJSON = true;
		
		if(isJSON) {
			String json = new String(payload, StandardCharsets.UTF_8);
			JSONObject obj = new JSONObject(json);
			setActive(obj.getBoolean("active"));
		}
	}
	
	public String toJSON() {

		String json = "{ "
				+ "\n\t\"active\" : " + active
				+ "\n}";
		
		return json;
	}
	public boolean isActive() {
		return active;
	}
	public void setActive(boolean active) {
		this.active = active;
	}
	public String getScope() {
		return scope;
	}
	public void setScope(String scope) {
		this.scope = scope;
	}
	public String getClient_id() {
		return client_id;
	}
	public void setClient_id(String client_id) {
		this.client_id = client_id;
	}
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public String getToken_type() {
		return token_type;
	}
	public void setToken_type(String token_type) {
		this.token_type = token_type;
	}
	public long getExp() {
		return exp;
	}
	public void setExp(long exp) {
		this.exp = exp;
	}
	public long getIat() {
		return iat;
	}
	public void setIat(long iat) {
		this.iat = iat;
	}
	public long getNbf() {
		return nbf;
	}
	public void setNbf(long nbf) {
		this.nbf = nbf;
	}
	public String getSub() {
		return sub;
	}
	public void setSub(String sub) {
		this.sub = sub;
	}
	public String getAud() {
		return aud;
	}
	public void setAud(String aud) {
		this.aud = aud;
	}
	public String getIss() {
		return iss;
	}
	public void setIss(String iss) {
		this.iss = iss;
	}
	public String getCti() {
		return cti;
	}
	public void setCti(String cti) {
		this.cti = cti;
	}
	@Override
	public String toString() {
		return "IntrospectResponse [active=" + active + ", scope=" + scope
				+ ", client_id=" + client_id + ", username=" + username
				+ ", token_type=" + token_type + ", exp=" + exp + ", iat="
				+ iat + ", nbf=" + nbf + ", sub=" + sub + ", aud=" + aud
				+ ", iss=" + iss + ", cti=" + cti + "]";
	}
	
	
	
}