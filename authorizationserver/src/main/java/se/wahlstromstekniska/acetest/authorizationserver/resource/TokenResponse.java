package se.wahlstromstekniska.acetest.authorizationserver.resource;

import java.nio.charset.StandardCharsets;

import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey.OutputControlLevel;
import org.json.JSONObject;

import se.wahlstromstekniska.acetest.authorizationserver.AccessToken;
import se.wahlstromstekniska.acetest.authorizationserver.Constants;

public class TokenResponse {

	private String accessToken = "";
	private String tokenType = "";
	private String csp = "";
	
	// TODO: It's right now a JWK serialized as a string, but we need to handle COSE in a good way also.
	private String key = null;
	private String pskIdentity = null;
	private EllipticCurveJsonWebKey rpk = null;
	
	public EllipticCurveJsonWebKey getRpk() {
		return rpk;
	}

	public void setRpk(EllipticCurveJsonWebKey rpk) {
		this.rpk = rpk;
	}

	public TokenResponse(byte[] payload, int contentFormat) throws Exception {
		if(contentFormat == MediaTypeRegistry.APPLICATION_JSON) {
			String json = new String(payload, StandardCharsets.UTF_8);
			JSONObject obj = new JSONObject(json);
			setAccessToken(obj.getString("access_token"));
			setTokenType(obj.getString("token_type"));
			setCsp(obj.getString("csp"));
			if(obj.has("key")) {
				setKey(obj.getJSONObject("key").toString());
			}
			if(obj.has("psk_identity")) {
				setPskIdentity(obj.getString("psk_identity"));
			}
			if(obj.has("rpk")) {
		    	String rpk = obj.getJSONObject("rpk").toString();
		    	EllipticCurveJsonWebKey rpkJWK = (EllipticCurveJsonWebKey) EllipticCurveJsonWebKey.Factory.newPublicJwk(rpk);
		    	setRpk(rpkJWK);
			}
		}
		else if(contentFormat == MediaTypeRegistry.APPLICATION_CBOR) {
			throw new Exception("Not implemented yet");
		}
		else {
			throw new Exception("Not implemented yet");
		}		
	}
	
	public TokenResponse(AccessToken accessToken, String tokenType, String csp, String key, String pskIdentity, EllipticCurveJsonWebKey rpk) {
		this.accessToken = accessToken.getAccessToken();
		this.tokenType = tokenType;
		this.csp = csp;
		this.key = key;
		this.pskIdentity = pskIdentity;
		this.rpk = rpk;
	}

	public byte[] toPayload(int contentFormat) {

		if(contentFormat == MediaTypeRegistry.APPLICATION_JSON) {
			String json = "{ "
					+ "\n\t\"access_token\" : \"" + accessToken + "\"," 
					+ "\n\t\"token_type\" : \"" + Constants.tokenTypePOP + "\","
					+ "\n\t\"csp\" : \"" + csp+ "\"";
			
			if(key != null) {
				json += ",\n\t\"key\" : " + key;
			}

			if(pskIdentity != null) {
				json += ",\n\t\"psk_identity\" : \"" + pskIdentity + "\"";
			}

			if(rpk != null) {
				json += ",\n\t\"rpk\" : " + rpk.toJson(OutputControlLevel.PUBLIC_ONLY) + "";
			}

			json += "\n}";
			
			return json.getBytes();
		}
		else if(contentFormat == MediaTypeRegistry.APPLICATION_CBOR) {
			return "not implemented yet".getBytes();
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

	public String getPskIdentity() {
		return pskIdentity;
	}

	public void setPskIdentity(String pskIdentity) {
		this.pskIdentity = pskIdentity;
	}


}
