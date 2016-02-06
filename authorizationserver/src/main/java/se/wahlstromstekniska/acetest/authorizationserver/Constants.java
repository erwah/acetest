package se.wahlstromstekniska.acetest.authorizationserver;


public class Constants {

	public static String grantTypeClientCreds = "client_credentials";

	public static String cspDTLS = "DTLS";
	
	public static String tokenTypePOP = "pop";

	public static final String TOKEN_RESOURCE = "token";

	public static final String INSTROSPECTION_RESOURCE = "introspect";

	public static final String AUTHZ_INFO_RESOURCE = "authz-info";

	public static final int MediaTypeRegistry_APPLICATION_JWT = 60001;
	public static final int MediaTypeRegistry_APPLICATION_CWT = 60002;
	
}
