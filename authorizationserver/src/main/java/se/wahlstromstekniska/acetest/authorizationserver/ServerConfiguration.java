package se.wahlstromstekniska.acetest.authorizationserver;


import java.io.InputStream;
import java.io.StringWriter;
import java.util.ArrayList;

import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
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
	
	private ArrayList<ResourceServer> resourceServers = new ArrayList<ResourceServer>();
	private ArrayList<ClientCredentials> clients = new ArrayList<ClientCredentials>();
	private int coapPort = 5683;
	private int coapsPort = 5684;
	
	private String trustStorePassword = null;
	private String trustStoreLocation = null;

	private String keyStorePassword = null;
	private String keyStoreLocation = null;

	private String psk = null;
	
	private EllipticCurveJsonWebKey signAndEncryptKey = null;
	
	private String configFilePath = "/config.json";
	
	protected ServerConfiguration() {

		try {
			
			logger.info("Loading authorization server configuration.");
			InputStream configIS = ServerConfiguration.class.getResourceAsStream(configFilePath);
			StringWriter configWriter = new StringWriter();
			IOUtils.copy(configIS,  configWriter, "UTF-8");
			setProperties(new JSONObject(configWriter.toString()));
			
			// load resource servers
			logger.debug("Loading configured resource servers.");

	    	JSONArray rsList = getProperties().getJSONArray("resourceservers");
	    	for (int i=0; i<rsList.length(); i++) {
	    	    JSONObject item = rsList.getJSONObject(i);

	    	    String aud = item.getString("aud");
	            ResourceServer rs = new ResourceServer(aud);

	    	    String csp = item.getString("csp");
	            rs.setCsp(csp);

	    	    String tokenFormat = item.getString("tokenformat");
	    	    if("JWT".equals(tokenFormat)) {
		            rs.setTokenFormat(ResourceServer.TOKEN_FORMAT_JWT);
	    	    }
	    	    else {
		            rs.setTokenFormat(ResourceServer.TOKEN_FORMAT_CWT);
	    	    }

	    	    String transportEncryption = item.getString("transportEncryption");
	    	    if("dtls-psk".equals(transportEncryption)) {
		            rs.setTransportEncryption(ResourceServer.TRANSPORT_ENCRYPTION_DTLS_PSK);
	    	    }
	    	    if("dtls-rpk".equals(transportEncryption)) {
		            rs.setTransportEncryption(ResourceServer.TRANSPORT_ENCRYPTION_DTLS_RPK);
	    	    }
	    	    if("dtls-cert".equals(transportEncryption)) {
		            rs.setTransportEncryption(ResourceServer.TRANSPORT_ENCRYPTION_DTLS_CERT);
	    	    }
	    	    if("oscon".equals(transportEncryption)) {
		            rs.setTransportEncryption(ResourceServer.TRANSPORT_ENCRYPTION_OSCON);
	    	    }
	    	    

	    	    String scopes = item.getString("scopes");
	    	    rs.setScopes(scopes);

	    	    JSONArray authorizedClients = item.getJSONArray("authorizedClients");
	        	for (int c=0; c<authorizedClients.length(); c++) {
	        	    String client = authorizedClients.getString(c);
	                rs.addAuthorizedClient(client);
	        	}
	        	
	            resourceServers.add(rs);
	    	}
	    	
	    	// load clients
	    	logger.debug("Loading configured clients.");
	        
	    	JSONArray clientList = getProperties().getJSONArray("clients");
	    	for (int i=0; i<clientList.length(); i++) {
	    	    JSONObject item = clientList.getJSONObject(i);
	    	    String clientID = item.getString("clientId");
	    	    String clientSecret = item.getString("clientSecret");

	    	    clients.add(new ClientCredentials(clientID, clientSecret));
	    	}
	    	
	    	// load port(s) config
	    	logger.debug("Loading ports resource servers.");
	    	setCoapPort(getProperties().getJSONObject("server").getInt("coapPort"));
	    	setCoapsPort(getProperties().getJSONObject("server").getInt("coapsPort"));

	    	// load trust store
	    	logger.debug("Loading trust store information.");
	    	setTrustStoreLocation(getProperties().getJSONObject("server").getString("trustStoreLocation"));
	    	setTrustStorePassword(getProperties().getJSONObject("server").getString("trustStorePassword"));

	    	// load key store
	    	logger.debug("Loading key store information.");
	    	setKeyStoreLocation(getProperties().getJSONObject("server").getString("keyStoreLocation"));
	    	setKeyStorePassword(getProperties().getJSONObject("server").getString("keyStorePassword"));

	    	// load psk
	    	logger.debug("Loading PSK.");
	    	setPsk(getProperties().getJSONObject("server").getString("psk"));

	    	// load sign and encryption key
	    	logger.debug("Loading sign and encryption key.");
	    	String key = getProperties().getJSONObject("server").getJSONObject("signAndEncryptKey").toString();
    		setSignAndEncryptKey((EllipticCurveJsonWebKey) EllipticCurveJsonWebKey.Factory.newPublicJwk(key.toString()));
		} catch (Exception e) {
			logger.fatal("Failed to parse configuration file: " + configFilePath);
			EllipticCurveJsonWebKey jwk;
			try {
				jwk = generateKey("AS signing key");
				String keyStr = jwk.toJson(OutputControlLevel.INCLUDE_PRIVATE);
				logger.info("Example key object to copy into the server.signAndEncryptKey property: " + keyStr);
			} catch (JoseException e1) {
				logger.error(e1);
			}
			
			logger.info("Shutting down server. Make sure to add a sign and encryption key to the config.json file.");

			System.exit(0);
		}
 
    	
	}
	
	public static ServerConfiguration getInstance() {
		if(instance == null) {
			try {
				instance = new ServerConfiguration();
			} catch (Exception e) {
				logger.fatal("Could not read properties file.", e);
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

	public ArrayList<ResourceServer> getResourceServers() {
		return resourceServers;
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

	public String getTrustStorePassword() {
		return trustStorePassword;
	}

	public void setTrustStorePassword(String trustStorePassword) {
		this.trustStorePassword = trustStorePassword;
	}

	public String getTrustStoreLocation() {
		return trustStoreLocation;
	}

	public void setTrustStoreLocation(String trustStoreLocation) {
		this.trustStoreLocation = trustStoreLocation;
	}

	public String getKeyStorePassword() {
		return keyStorePassword;
	}

	public void setKeyStorePassword(String keyStorePassword) {
		this.keyStorePassword = keyStorePassword;
	}

	public String getKeyStoreLocation() {
		return keyStoreLocation;
	}

	public void setKeyStoreLocation(String keyStoreLocation) {
		this.keyStoreLocation = keyStoreLocation;
	}

	public String getPsk() {
		return psk;
	}

	public void setPsk(String psk) {
		this.psk = psk;
	}

	public EllipticCurveJsonWebKey getSignAndEncryptKey() {
		return signAndEncryptKey;
	}

	public void setSignAndEncryptKey(EllipticCurveJsonWebKey signAndEncryptKey) {
		this.signAndEncryptKey = signAndEncryptKey;
	}
	
}
