package se.wahlstromstekniska.acetest.authorizationserver;

import java.nio.charset.StandardCharsets;

import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.json.JSONObject;

import se.wahlstromstekniska.acetest.authorizationserver.exception.InvalidJsonException;

public class ErrorResponse {
	
	private String error = "";
	
	private static String errorTemplateStart = "{\"error\":\"";
	private static String errorTemplateEnd = "\"}"; 

	public ErrorResponse(byte[] payload, int contentFormat) throws Exception {
		if(contentFormat == MediaTypeRegistry.APPLICATION_JSON) {
			String json = new String(payload, StandardCharsets.UTF_8);
			if(Utils.isJSONValid(json)) {
				JSONObject obj = new JSONObject(json);
				setError(obj.getString("error"));
			} 
			else {
				throw new InvalidJsonException("Error message in payload is not valid JSON."); 
			}
		}
		else if(contentFormat == MediaTypeRegistry.APPLICATION_CBOR) {
			throw new Exception("Not implemented");
		}
		else {
			throw new Exception("Not implemented.");
		}

	}
	
	public static byte[] getInvalidRequest(int contentFormat) throws Exception {
		if(contentFormat == MediaTypeRegistry.APPLICATION_JSON) {
			String s = errorTemplateStart + "invalid_request" + errorTemplateEnd;
			return s.getBytes();
		}
		else if(contentFormat == MediaTypeRegistry.APPLICATION_CBOR) {
			return "not implemented".getBytes();
		}
		else {
			throw new Exception("Not implemented.");
		}
	}

	public static byte[] getInvalidClient(int contentFormat) throws Exception {
		if(contentFormat == MediaTypeRegistry.APPLICATION_JSON) {
			String s = errorTemplateStart + "invalid_client" + errorTemplateEnd;
			return s.getBytes();
		}
		else if(contentFormat == MediaTypeRegistry.APPLICATION_CBOR) {
			return "not implemented".getBytes();
		}
		else {
			throw new Exception("Not implemented.");
		}
	}

	public static byte[] getInvalidGrant(int contentFormat) throws Exception {
		if(contentFormat == MediaTypeRegistry.APPLICATION_JSON) {
			String s = errorTemplateStart + "invalid_grant" + errorTemplateEnd;
			return s.getBytes();
		}
		else if(contentFormat == MediaTypeRegistry.APPLICATION_CBOR) {
			return "not implemented".getBytes();
		}
		else {
			throw new Exception("Not implemented.");
		}
	}

	public static byte[] getUnauthorizedClient(int contentFormat) throws Exception {
		if(contentFormat == MediaTypeRegistry.APPLICATION_JSON) {
			String s = errorTemplateStart + "unauthorized_client" + errorTemplateEnd;
			return s.getBytes();
		}
		else if(contentFormat == MediaTypeRegistry.APPLICATION_CBOR) {
			return "not implemented".getBytes();
		}
		else {
			throw new Exception("Not implemented.");
		}
	}

	public static byte[] getUnsupportedGrantType(int contentFormat) throws Exception {
		if(contentFormat == MediaTypeRegistry.APPLICATION_JSON) {
			String s = errorTemplateStart + "unsupported_grant_type" + errorTemplateEnd;
			return s.getBytes();
		}
		else if(contentFormat == MediaTypeRegistry.APPLICATION_CBOR) {
			return "not implemented".getBytes();
		}
		else {
			throw new Exception("Not implemented.");
		}
	}

	public static byte[] getInvalidScope(int contentFormat) throws Exception {
		if(contentFormat == MediaTypeRegistry.APPLICATION_JSON) {
			String s = errorTemplateStart + "invalid_scope" + errorTemplateEnd;
			return s.getBytes();
		}
		else if(contentFormat == MediaTypeRegistry.APPLICATION_CBOR) {
			return "not implemented".getBytes();
		}
		else {
			throw new Exception("Not implemented.");
		}
	}

	public static byte[] getInternalServerError(int contentFormat) throws Exception {
		if(contentFormat == MediaTypeRegistry.APPLICATION_JSON) {
			String s = errorTemplateStart + "internal_server_error" + errorTemplateEnd;
			return s.getBytes();
		}
		else if(contentFormat == MediaTypeRegistry.APPLICATION_CBOR) {
			return "not implemented".getBytes();
		}
		else {
			throw new Exception("Not implemented.");
		}
	}

	public String getError() {
		return error;
	}

	public void setError(String error) {
		this.error = error;
	}

}
