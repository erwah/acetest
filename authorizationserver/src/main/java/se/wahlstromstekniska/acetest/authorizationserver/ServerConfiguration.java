package se.wahlstromstekniska.acetest.authorizationserver;


import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;

import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.jose4j.json.internal.json_simple.parser.ParseException;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKey.OutputControlLevel;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.lang.JoseException;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Reads properties and authorization servers keys for signing and encryption.
 * WARNING: Class uses a insecure key file based key storage and this is NOT recommended 
 * to be used in production.
 * 
 * @author erikw
 *
 */
public class ServerConfiguration {

	final static Logger logger = Logger.getLogger(ServerConfiguration.class);

	private static ServerConfiguration instance = null;
	private static JSONObject properties = null;
	private static EllipticCurveJsonWebKey authorizationServerKey = null;
	
	private ArrayList<ResourceServer> resourceServers = new ArrayList<ResourceServer>();
	private ArrayList<ClientCredentials> clients = new ArrayList<ClientCredentials>();
	

	
	protected ServerConfiguration() throws IOException, JoseException, ParseException {

		logger.info("Loading authorization server configuration.");
		InputStream configIS = ServerConfiguration.class.getResourceAsStream("/config.json");
		StringWriter configWriter = new StringWriter();
		IOUtils.copy(configIS,  configWriter, "UTF-8");
		setProperties(new JSONObject(configWriter.toString()));
		
		// TODO: validate config

		try {
			
	    	logger.info("Loading authorization server keys.");
			InputStream keyIS = new FileInputStream(new File("authorizationserver.key"));
			StringWriter keyWriter = new StringWriter();
			IOUtils.copy(keyIS,  keyWriter, "UTF-8");
			
			JSONObject jsonKey = new JSONObject(keyWriter.toString());
			authorizationServerKey = (EllipticCurveJsonWebKey) EllipticCurveJsonWebKey.Factory.newPublicJwk(jsonKey.toString());
			
			// TODO: validate key format

		} catch (Exception e) {
			logger.info("No keys found for authorization server. Generating keys...");
			EllipticCurveJsonWebKey jwk = generateKey("AS signing key");
			
			String keyStr = jwk.toJson(OutputControlLevel.INCLUDE_PRIVATE);
			PrintWriter keyFileWriter = new PrintWriter("authorizationserver.key", "UTF-8");
			keyFileWriter.println(keyStr);
			keyFileWriter.close();
			
			// only adding if successfully written to disk
			authorizationServerKey = jwk;
		}
		
		// load resource servers
    	logger.info("Loading configured resource servers.");

    	JSONArray rsList = getProperties().getJSONArray("resourceservers");
    	for (int i=0; i<rsList.length(); i++) {
    	    JSONObject item = rsList.getJSONObject(i);

    	    String aud = item.getString("aud");
            ResourceServer rs = new ResourceServer(aud);

    	    String csp = item.getString("csp");
            rs.setCsp(csp);

    	    JSONArray authorizedClients = item.getJSONArray("authorizedClients");
        	for (int c=0; c<authorizedClients.length(); c++) {
        	    String client = authorizedClients.getString(c);
                rs.addAuthorizedClient(client);
        	}
        	
            resourceServers.add(rs);
    	}
    	
    	// load clients
    	logger.info("Loading configured clients.");
        
    	JSONArray clientList = getProperties().getJSONArray("clients");
    	for (int i=0; i<clientList.length(); i++) {
    	    JSONObject item = clientList.getJSONObject(i);
    	    String clientID = item.getString("client_id");
    	    String clientSecret = item.getString("client_secret");

    	    clients.add(new ClientCredentials(clientID, clientSecret));
    	}

	}
	
	public static ServerConfiguration getInstance() {
		if(instance == null) {
			try {
				instance = new ServerConfiguration();
			} catch (Exception e) {
				logger.fatal("Could not read properties file.");
				e.printStackTrace();
			}
		}
		return instance;
	}

	public ResourceServer getResourceServer(String aud) {
		ResourceServer foundRS = null;
		if(aud != null && aud.trim().length() != 0) {
			for (ResourceServer rs : resourceServers) {
				if(rs.getAud().equals(aud.trim())) {
					foundRS = rs;
				}
			}
		}
		return foundRS;
	}

	private EllipticCurveJsonWebKey generateKey(String kid) throws JoseException {
	    EllipticCurveJsonWebKey jwk = EcJwkGenerator.generateJwk(EllipticCurves.P256);
		jwk.setKeyId(kid);
		return jwk;
	}
	
	public ClientCredentials getClient(String clientId) {
		ClientCredentials found = null;
		
		for (ClientCredentials client : clients) {
			if(client.getClient_id().equals(clientId)) {
				found = client;
			}
		}
		return found;
	}
	
	public static JSONObject getProperties() {
		return properties;
	}

	public static void setProperties(JSONObject properties) {
		ServerConfiguration.properties = properties;
	}

	public EllipticCurveJsonWebKey getAuthorizationServerKey() {
		return authorizationServerKey;
	}
	
}
