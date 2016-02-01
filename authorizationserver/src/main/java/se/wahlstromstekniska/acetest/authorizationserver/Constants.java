package se.wahlstromstekniska.acetest.authorizationserver;

import org.eclipse.californium.core.coap.MediaTypeRegistry;

public class Constants {

	public static String grantTypeClientCreds = "client_credentials";

	public static String cspDTLS = "DTLS";
	
	public static String tokenTypePOP = "pop";

	public static final String TOKEN_RESOURCE = "token";

	public static final String INSTROSPECTION_RESOURCE = "introspect";

	// TODO: register this
	public static final int MediaTypeRegistry_APPLICATION_CBOR = 60001;

}
