package se.wahlstromstekniska.acetest.systemsetup;

import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey.OutputControlLevel;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.lang.JoseException;
import org.json.JSONObject;

public class SystemSetup {

	private static SecureRandom random = new SecureRandom();

	static EllipticCurveJsonWebKey signAndEncryptKey = generateKey("AS sign and encryption key");
	static EllipticCurveJsonWebKey clientEncryptKey = generateKey("Clients encryption key");
	static EllipticCurveJsonWebKey rsDtlsRPK = generateKey("RS DTLS RPK");
	
	static String asPskIdentity = generateRandomString();
	static String asPskKey = generateRandomString();
	static String clientSecret = generateRandomString();

	
	// TODO: remove. It's there now for clarity when developing.
//	static String clientId =  generateRandomString();
//	static String aud =  generateRandomString();
	static String clientId =  "myClient";
	static String aud =  "tempSensor";

	static String scopes = "read write";
	
	static String authorizationServerConfigPath = "../authorizationserver/src/main/resources/authorizationserver.json";
	static String resourceServerConfigPath = "../resourceserver/src/main/resources/resourceserver.json";
	static String clientConfigPath = "../client/src/main/resources/client.json";
	
	public static void main(String[] args) {
		
		PrintWriter writer = null;
		
		try {
			String asConfig = generateASConfig();
			System.out.println("----------------- Authorization Server Config --------------------------------------");
			System.out.println(asConfig);
			writer = new PrintWriter(authorizationServerConfigPath, "UTF-8");
			writer.println(asConfig);
			writer.close();


			System.out.println("-----------------    Resource Server Config   --------------------------------------");
			String rsConfig = generateRSConfig();
			System.out.println(rsConfig);
			writer = new PrintWriter(resourceServerConfigPath, "UTF-8");
			writer.println(rsConfig);
			writer.close();

			System.out.println("-----------------       Client Config         --------------------------------------");
			String clientConfig = generateClientConfig();
			System.out.println(clientConfig);
			writer = new PrintWriter(clientConfigPath, "UTF-8");
			writer.println(clientConfig);
			writer.close();

		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}


	private static EllipticCurveJsonWebKey generateKey(String kid)  {
		EllipticCurveJsonWebKey jwk = null;
		try {
		    jwk = EcJwkGenerator.generateJwk(EllipticCurves.P256);
			jwk.setKeyId(kid);
		} catch(Exception e) {
			e.printStackTrace();
		}
		return jwk;
	}

	public static String generateRandomString() {
		return new BigInteger(130, random).toString(32);
	}

	private static String generateASConfig() throws JoseException {
		
		String json = "{" 
			+ "\"authorizationserverconfig\" : {"
				+ "\"authorizationserver\" : {"
				+ 	"\"coapPort\": 5683,"
				+	"\"coapsPort\" : 5684,"
				+	"\"pskIdentity\" : \"" + asPskIdentity + "\","
				+	"\"pskKey\" : \"" + asPskKey + "\","
				+	"\"signAndEncryptKey\" : " + signAndEncryptKey.toJson(OutputControlLevel.INCLUDE_PRIVATE)
				+ "},"
				+"\"clients\" : ["
				+"	{"
				+		"\"clientId\":\"" + clientId + "\","
				+		"\"clientSecret\" : \"" + clientSecret + "\","
				+		"\"keyEncryptionMethod\": \"ec\","
				+		"\"encryptionKey\": " + clientEncryptKey.toJson(OutputControlLevel.PUBLIC_ONLY)
				+  "}"
				+"],"
				+"\"resourceservers\" : ["
				+	"{"
				+		"\"aud\":\"" + aud + "\","
				+		"\"tokenformat\":\"JWT\","
				+		"\"csp\" : \"DLTS\","
				+		"\"authorizedClients\" : [\"" + clientId + "\"],"
				+		"\"scopes\" : \"" + scopes + "\","
				+		"\"transportEncryption\" : \"dtls-psk\","
				+		"\"serverKey\": " + rsDtlsRPK.toJson(OutputControlLevel.PUBLIC_ONLY) + ","
				+	"}"
				+"]"
				+"}"
			+"}";
		
		JSONObject o = new JSONObject(json);
        return o.toString(4);
	}


	private static String generateRSConfig() throws JoseException {
		String json = "{" 
			+ "\"resourceserverconfig\" : {"
			+	 "\"resourceserver\" : {"
			+		"\"aud\":\"" + aud + "\","
			+	 	"\"coapPort\": 6683,"
			+		"\"coapsPort\" : 6684,"
			+		"\"rpk\" : " + rsDtlsRPK.toJson(OutputControlLevel.INCLUDE_PRIVATE)
			+	 "},"
			+	 "\"authorizationserver\" : {"
			+		"\"asSignKey\" : " + signAndEncryptKey.toJson(OutputControlLevel.PUBLIC_ONLY) + ""
			+	 "}"
			+ "}"
			+"}";
		
		JSONObject o = new JSONObject(json);
        return o.toString(4);
	}
	

	private static String generateClientConfig() throws JoseException {
		String json = "{" 
			+ "\"clientconfig\" : {"
			+	 "\"client\" : {"
			+		"\"encryptionKey\" : " + clientEncryptKey.toJson(OutputControlLevel.INCLUDE_PRIVATE) + ","
			+	 	"\"client_id\": \"" + clientId + "\","
			+	 	"\"client_secret\": \"" + clientSecret + "\","
			+	 "},"
			+	 "\"authorizationserver\" : {"
			+	 	"\"coapPort\": 5683,"
			+		"\"coapsPort\" : 5684,"
			+	 	"\"pskIdentity\": \"" + asPskIdentity + "\","
			+		"\"pskKey\" : \"" + asPskKey + "\""
			+	 "},"
			+	 "\"resourceserver\" : {"
			+	 	"\"coapPort\": 6683,"
			+		"\"coapsPort\" : 6684,"
			+		"\"aud\" : " + aud + ","
			+		"\"scopes\" : " + scopes
			+	 "}"
			+ "}"
			+"}";
		
		JSONObject o = new JSONObject(json);
        return o.toString(4);
              
	}	
}
