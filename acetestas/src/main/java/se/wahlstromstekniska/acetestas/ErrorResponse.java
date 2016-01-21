package se.wahlstromstekniska.acetestas;

public class ErrorResponse {
	
	private static String errorTemplateStart = "{\"error\":\"";
	private static String errorTemplateEnd = "\"}"; 

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

}
