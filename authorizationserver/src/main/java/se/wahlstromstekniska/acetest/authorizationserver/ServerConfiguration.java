package se.wahlstromstekniska.acetest.authorizationserver;


import java.io.InputStream;
import java.io.StringWriter;
import java.util.ArrayList;

import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
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
	private ArrayList<Client> clients = new ArrayList<Client>();
	private int coapPort = 5683;
	private int coapsPort = 5684;
	
	private String pskIdentity = null;
	private String pskKey = null;
		
	private EllipticCurveJsonWebKey signAndEncryptKey = null;
	
	private String configFilePath = "/authorizationserver.json";
	
	protected ServerConfiguration() {

		try {
			
			logger.info("Loading authorization server configuration.");
			InputStream configIS = ServerConfiguration.class.getResourceAsStream(configFilePath);
			StringWriter configWriter = new StringWriter();
			IOUtils.copy(configIS,  configWriter, "UTF-8");
			setProperties(new JSONObject(configWriter.toString()));
			
			// load resource servers
			logger.debug("Loading configured resource servers.");

	    	JSONArray rsList = getProperties().getJSONObject("authorizationserverconfig").getJSONArray("resourceservers");
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
	        	
		    	String rpk = item.getJSONObject("serverKey").toString();
		    	EllipticCurveJsonWebKey rpkJWK = (EllipticCurveJsonWebKey) EllipticCurveJsonWebKey.Factory.newPublicJwk(rpk);
		    	rs.setRPK(rpkJWK);
	        	
	            resourceServers.add(rs);
	    	}
	    	
	    	// load clients
	    	logger.debug("Loading configured clients.");
	        
	    	JSONArray clientList = getProperties().getJSONObject("authorizationserverconfig").getJSONArray("clients");
	    	for (int i=0; i<clientList.length(); i++) {
	    	    JSONObject item = clientList.getJSONObject(i);
	    	    String clientID = item.getString("clientId");
	    	    String clientSecret = item.getString("clientSecret");
	    	    
		    	String encryptionKey = item.getJSONObject("encryptionKey").toString();
		    	EllipticCurveJsonWebKey jwk = (EllipticCurveJsonWebKey) EllipticCurveJsonWebKey.Factory.newPublicJwk(encryptionKey);

	    	    clients.add(new Client(clientID, clientSecret, jwk));
	    	}
	    	
	    	// load port(s) config
	    	logger.debug("Loading ports resource servers.");
	    	setCoapPort(getProperties().getJSONObject("authorizationserverconfig").getJSONObject("authorizationserver").getInt("coapPort"));
	    	setCoapsPort(getProperties().getJSONObject("authorizationserverconfig").getJSONObject("authorizationserver").getInt("coapsPort"));

	    	// load psk identity used to connect to AS securely from the client
	    	logger.debug("Loading PSK.");
	    	setPskKey(getProperties().getJSONObject("authorizationserverconfig").getJSONObject("authorizationserver").getString("pskKey"));
	    	setPskIdentity(getProperties().getJSONObject("authorizationserverconfig").getJSONObject("authorizationserver").getString("pskIdentity"));

	    	// load sign and encryption key
	    	logger.debug("Loading sign and encryption key.");
	    	String key = getProperties().getJSONObject("authorizationserverconfig").getJSONObject("authorizationserver").getJSONObject("signAndEncryptKey").toString();
    		setSignAndEncryptKey((EllipticCurveJsonWebKey) EllipticCurveJsonWebKey.Factory.newPublicJwk(key.toString()));
		} catch (Exception e) {
			logger.fatal("Failed to parse configuration file: " + configFilePath);
			logger.fatal(e);
			logger.fatal("Run the system setup project. It will automatically create a dummy configuraton to get you started.");
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
	
	public Client getClient(String clientId) {
		Client found = null;
		
		for (Client client : clients) {
			if(client.getClient_id().equals(clientId)) {
				found = client;
			}
		}
		return found;
	}

	public ArrayList<Client> getClients() {
		return clients;
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

	public String getPskIdentity() {
		return pskIdentity;
	}

	public void setPskIdentity(String pskIdentity) {
		this.pskIdentity = pskIdentity;
	}

	public String getPskKey() {
		return pskKey;
	}

	public void setPskKey(String pskKey) {
		this.pskKey = pskKey;
	}
	
	public EllipticCurveJsonWebKey getSignAndEncryptKey() {
		return signAndEncryptKey;
	}

	public void setSignAndEncryptKey(EllipticCurveJsonWebKey signAndEncryptKey) {
		this.signAndEncryptKey = signAndEncryptKey;
	}

}
