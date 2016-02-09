package se.wahlstromstekniska.acetest.client;


import java.io.InputStream;
import java.io.StringWriter;

import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.json.JSONObject;

import se.wahlstromstekniska.acetest.authorizationserver.ServerConfiguration;

public class ClientConfiguration {

	final static Logger logger = Logger.getLogger(ClientConfiguration.class);

	private static ClientConfiguration instance = null;

	private String clientId;
	private String clientSecret;

	private int asCoapPort;
	private int asCoapsPort;
	private int rsCoapPort;
	private int rsCoapsPort;
	
	private String asPskIdentity;
	private String asPskKey;

	private String rsAud;
	private String rsScopes;

	private EllipticCurveJsonWebKey encryptionKey = null;
	
	private static JSONObject properties = null;
	
	private String configFilePath = "/client.json";
	
	
	protected ClientConfiguration() {

		try {
			
			logger.info("Loading client configuration.");
			InputStream configIS = ServerConfiguration.class.getResourceAsStream(configFilePath);
			StringWriter configWriter = new StringWriter();
			IOUtils.copy(configIS,  configWriter, "UTF-8");
			setProperties(new JSONObject(configWriter.toString()));
			
	    	// load port(s) config
	    	logger.debug("Loading ports for resource servers.");
	    	setRsCoapPort(getProperties().getJSONObject("clientconfig").getJSONObject("resourceserver").getInt("coapPort"));
	    	setRsCoapsPort(getProperties().getJSONObject("clientconfig").getJSONObject("resourceserver").getInt("coapsPort"));

	    	// load resource servers aud
	    	setRsAud(getProperties().getJSONObject("clientconfig").getJSONObject("resourceserver").getString("aud"));
	    	setRsScopes(getProperties().getJSONObject("clientconfig").getJSONObject("resourceserver").getString("scopes"));

	    	logger.debug("Loading ports for authorization server.");
	    	setAsCoapPort(getProperties().getJSONObject("clientconfig").getJSONObject("authorizationserver").getInt("coapPort"));
	    	setAsCoapsPort(getProperties().getJSONObject("clientconfig").getJSONObject("authorizationserver").getInt("coapsPort"));
	    	
	    	// load psk identity used to connect to AS securely from the client
	    	logger.debug("Loading PSK.");
	    	setAsPskIdentity(getProperties().getJSONObject("clientconfig").getJSONObject("authorizationserver").getString("pskIdentity"));
	    	setAsPskKey(getProperties().getJSONObject("clientconfig").getJSONObject("authorizationserver").getString("pskKey"));

	    	String key = getProperties().getJSONObject("clientconfig").getJSONObject("client").getJSONObject("encryptionKey").toString();
	    	setEncryptionKey((EllipticCurveJsonWebKey) EllipticCurveJsonWebKey.Factory.newPublicJwk(key.toString()));

	    	setClientId(getProperties().getJSONObject("clientconfig").getJSONObject("client").getString("client_id"));
	    	setClientSecret(getProperties().getJSONObject("clientconfig").getJSONObject("client").getString("client_secret"));

		} catch (Exception e) {
			logger.fatal("Failed to parse configuration file: " + configFilePath);
			logger.fatal(e);
			logger.fatal("Run the system setup project. It will automatically create a dummy configuraton to get you started.");
			System.exit(0);
		}
 
    	
	}
	
	public static ClientConfiguration getInstance() {
		if(instance == null) {
			try {
				instance = new ClientConfiguration();
			} catch (Exception e) {
				logger.fatal("Could not read properties file.");
				e.printStackTrace();
			}
		}
		return instance;
	}


	public static JSONObject getProperties() {
		return properties;
	}

	public static void setProperties(JSONObject properties) {
		ClientConfiguration.properties = properties;
	}

	public int getAsCoapPort() {
		return asCoapPort;
	}

	public void setAsCoapPort(int asCoapPort) {
		this.asCoapPort = asCoapPort;
	}

	public int getAsCoapsPort() {
		return asCoapsPort;
	}

	public void setAsCoapsPort(int asCoapsPort) {
		this.asCoapsPort = asCoapsPort;
	}

	public int getRsCoapPort() {
		return rsCoapPort;
	}

	public void setRsCoapPort(int rsCoapPort) {
		this.rsCoapPort = rsCoapPort;
	}

	public int getRsCoapsPort() {
		return rsCoapsPort;
	}

	public void setRsCoapsPort(int rsCoapsPort) {
		this.rsCoapsPort = rsCoapsPort;
	}

	public EllipticCurveJsonWebKey getEncryptionKey() {
		return encryptionKey;
	}

	public void setEncryptionKey(EllipticCurveJsonWebKey encryptionKey) {
		this.encryptionKey = encryptionKey;
	}

	public String getAsPskIdentity() {
		return asPskIdentity;
	}

	public void setAsPskIdentity(String asPskIdentity) {
		this.asPskIdentity = asPskIdentity;
	}

	public String getAsPskKey() {
		return asPskKey;
	}

	public void setAsPskKey(String asPskKey) {
		this.asPskKey = asPskKey;
	}

	public String getRsAud() {
		return rsAud;
	}

	public void setRsAud(String rsAud) {
		this.rsAud = rsAud;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	public String getRsScopes() {
		return rsScopes;
	}

	public void setRsScopes(String rsScopes) {
		this.rsScopes = rsScopes;
	}

}
