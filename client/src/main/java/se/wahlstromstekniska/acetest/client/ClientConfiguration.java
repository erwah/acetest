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
	
	private int asCoapPort;
	private int asCoapsPort;
	private int rsCoapPort;
	private int rsCoapsPort;
	
	private String asPskIdentity;
	private String asPskKey;
	
	private EllipticCurveJsonWebKey encryptionKey = null;
	
	private static JSONObject properties = null;
	
	private String configFilePath = "/client_config.json";
	
	
	protected ClientConfiguration() {

		try {
			
			logger.info("Loading client configuration.");
			InputStream configIS = ServerConfiguration.class.getResourceAsStream(configFilePath);
			StringWriter configWriter = new StringWriter();
			IOUtils.copy(configIS,  configWriter, "UTF-8");
			setProperties(new JSONObject(configWriter.toString()));
			
	    	// load port(s) config
	    	logger.debug("Loading ports for resource servers.");
	    	setRsCoapPort(getProperties().getJSONObject("client").getInt("rsCoapPort"));
	    	setRsCoapsPort(getProperties().getJSONObject("client").getInt("rsCoapsPort"));

	    	logger.debug("Loading ports for resource servers.");
	    	setAsCoapPort(getProperties().getJSONObject("client").getInt("asCoapPort"));
	    	setAsCoapsPort(getProperties().getJSONObject("client").getInt("asCoapsPort"));
	    	
	    	// load psk identity used to connect to AS securely from the client
	    	logger.debug("Loading PSK.");
	    	setAsPskIdentity(getProperties().getJSONObject("client").getString("asPskIdentity"));
	    	setAsPskKey(getProperties().getJSONObject("client").getString("asPskKey"));

	    	String key = getProperties().getJSONObject("client").getJSONObject("encryptionKey").toString();
	    	setEncryptionKey((EllipticCurveJsonWebKey) EllipticCurveJsonWebKey.Factory.newPublicJwk(key.toString()));
    		
		} catch (Exception e) {
			logger.fatal("Failed to parse configuration file: " + configFilePath);
			logger.fatal(e);
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

}
