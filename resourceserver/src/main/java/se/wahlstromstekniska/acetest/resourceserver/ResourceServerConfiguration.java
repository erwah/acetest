package se.wahlstromstekniska.acetest.resourceserver;


import java.io.InputStream;
import java.io.StringWriter;
import java.security.PublicKey;
import java.util.ArrayList;

import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.eclipse.californium.scandium.dtls.pskstore.InMemoryPskStore;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.json.JSONObject;

import se.wahlstromstekniska.acetest.authorizationserver.ServerConfiguration;

public class ResourceServerConfiguration {

	final static Logger logger = Logger.getLogger(ResourceServerConfiguration.class);

	private static ResourceServerConfiguration instance = null;
	
	private int coapPort = 6683;
	private int coapsPort = 6684;
	
	private String psk = null;
		
	private static JSONObject properties = null;
	
	private String configFilePath = "/resourceserver.json";

	private String aud;

	// TODO: Handle life cycle management of keys, add tokens right next to the public keys
	private InMemoryPskStore pskStorage = new InMemoryPskStore();

	// TODO: Handle life cycle management of keys, add tokens right next to the public keys
	private ArrayList<PublicKey> publicKeyStorage = new ArrayList<PublicKey>();

	private EllipticCurveJsonWebKey rpk = null;

	private EllipticCurveJsonWebKey asSignKey = null;
	
	protected ResourceServerConfiguration() {

		try {
			
			logger.info("Loading resource server configuration.");
			InputStream configIS = ServerConfiguration.class.getResourceAsStream(configFilePath);
			StringWriter configWriter = new StringWriter();
			IOUtils.copy(configIS,  configWriter, "UTF-8");
			setProperties(new JSONObject(configWriter.toString()));
			
	    	// load port(s) config
	    	logger.debug("Loading ports resource servers.");
	    	setCoapPort(getProperties().getJSONObject("resourceserverconfig").getJSONObject("resourceserver").getInt("coapPort"));
	    	setCoapsPort(getProperties().getJSONObject("resourceserverconfig").getJSONObject("resourceserver").getInt("coapsPort"));

	    	setAud(getProperties().getJSONObject("resourceserverconfig").getJSONObject("resourceserver").getString("aud"));

	    	String key = getProperties().getJSONObject("resourceserverconfig").getJSONObject("resourceserver").getJSONObject("rpk").toString();
    		setRpk((EllipticCurveJsonWebKey) EllipticCurveJsonWebKey.Factory.newPublicJwk(key.toString()));

	    	String signKey = getProperties().getJSONObject("resourceserverconfig").getJSONObject("authorizationserver").getJSONObject("asSignKey").toString();
    		setAsSignKey((EllipticCurveJsonWebKey) EllipticCurveJsonWebKey.Factory.newPublicJwk(signKey.toString()));
    		
		} catch (Exception e) {
			logger.fatal("Failed to parse configuration file: " + configFilePath);
			logger.fatal(e);
			logger.fatal("Run the system setup project. It will automatically create a dummy configuraton to get you started.");
			System.exit(0);
		}
 
    	
	}
	
	public static ResourceServerConfiguration getInstance() {
		if(instance == null) {
			try {
				instance = new ResourceServerConfiguration();
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
		ResourceServerConfiguration.properties = properties;
	}

	public int getCoapPort() {
		return coapPort;
	}

	public void setCoapPort(int coapPort) {
		this.coapPort = coapPort;
	}

	public int getCoapsPort() {
		return coapsPort;
	}

	public void setCoapsPort(int coapsPort) {
		this.coapsPort = coapsPort;
	}

	public String getPsk() {
		return psk;
	}

	public void setPsk(String psk) {
		this.psk = psk;
	}

	public InMemoryPskStore getPskStorage() {
		return pskStorage;
	}

	public void setPskStorage(InMemoryPskStore pskStorage) {
		this.pskStorage = pskStorage;
	}

	public ArrayList<PublicKey> getPublicKeyStorage() {
		return publicKeyStorage;
	}

	public void setPublicKeyStorage(ArrayList<PublicKey> publicKeyStorage) {
		this.publicKeyStorage = publicKeyStorage;
	}

	public EllipticCurveJsonWebKey getRpk() {
		return rpk;
	}

	public void setRpk(EllipticCurveJsonWebKey rpk) {
		this.rpk = rpk;
	}

	public EllipticCurveJsonWebKey getAsSignKey() {
		return asSignKey;
	}

	public void setAsSignKey(EllipticCurveJsonWebKey asSignKey) {
		this.asSignKey = asSignKey;
	}

	public String getAud() {
		return aud;
	}

	public void setAud(String aud) {
		this.aud = aud;
	}

}
