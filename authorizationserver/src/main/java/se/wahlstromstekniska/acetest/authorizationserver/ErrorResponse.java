package se.wahlstromstekniska.acetest.authorizationserver;

import java.nio.charset.StandardCharsets;

import org.json.JSONObject;

import se.wahlstromstekniska.acetest.authorizationserver.exception.InvalidJsonException;

public class ErrorResponse {
	
	private String error = "";
	
	private static String errorTemplateStart = "{\"error\":\"";
	private static String errorTemplateEnd = "\"}"; 

	public ErrorResponse(byte[] payload) throws InvalidJsonException {
		// is it JSON or CBOR?
		// TODO: do the real check and add CBOR support
		boolean isJSON = true;
		
		if(isJSON) {
			String json = new String(payload, StandardCharsets.UTF_8);
			if(Utils.isJSONValid(json)) {
				JSONObject obj = new JSONObject(json);
				setError(obj.getString("error"));
			} 
			else {
				throw new InvalidJsonException("Error message in payload is not valid JSON."); 
			}
		}
	}
	
	public static String getInvalidRequest() {
		return errorTemplateStart + "invalid_request" + errorTemplateEnd;
	}

	public static String getInvalidClient() {
		return errorTemplateStart + "invalid_client" + errorTemplateEnd;
	}

	public static String getInvalidGrant() {
		return errorTemplateStart + "invalid_grant" + errorTemplateEnd;
	}

	public static String getUnauthorizedClient() {
		return errorTemplateStart + "unauthorized_client" + errorTemplateEnd;
	}

	public static String getUnsupportedGrantType() {
		return errorTemplateStart + "unsupported_grant_type" + errorTemplateEnd;
	}

	public static String getInvalidScope() {
		return errorTemplateStart + "invalid_scope" + errorTemplateEnd;
	}

	public static String getInternalServerError() {
		return errorTemplateStart + "internal_server_error" + errorTemplateEnd;
	}

	public String getError() {
		return error;
	}

	public void setError(String error) {
		this.error = error;
	}

}
