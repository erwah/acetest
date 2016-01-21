package se.wahlstromstekniska.acetestas;

import java.util.ArrayList;

public class ManagedResourceServers {

	private static ManagedResourceServers instance = null;
	private ArrayList<ResourceServer> list = new ArrayList<ResourceServer>();
	
	protected ManagedResourceServers() {
	
	}
	
	public static ManagedResourceServers getInstance() {
		if(instance == null) {
			instance = new ManagedResourceServers();
		}
		return instance;
	}
	
	public void addResourceServer(ResourceServer newRS) throws Exception {
		for (ResourceServer rs : list) {
			if(rs.getAud().equals(newRS.getAud())) {
				throw new Exception("Trying to add multiple resource servers with same audience identifier.");
			}
		}
		list.add(newRS);
	}
	
	public void removeResourceServer(String aud) {
		ResourceServer foundRS = null;
		for (ResourceServer rs : list) {
			if(rs.getAud().equals(aud.trim())) {
				foundRS = rs;
			}
		}
		if(foundRS != null) {
			list.remove(foundRS);
		}
	}

	public ResourceServer getResourceServer(String aud) {
		ResourceServer foundRS = null;
		if(aud != null && aud.trim().length() != 0) {
			for (ResourceServer rs : list) {
				if(rs.getAud().equals(aud.trim())) {
					foundRS = rs;
				}
			}
		}
		return foundRS;
	}
		
}
