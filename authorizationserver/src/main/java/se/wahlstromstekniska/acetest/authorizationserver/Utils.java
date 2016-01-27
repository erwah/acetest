package se.wahlstromstekniska.acetest.authorizationserver;

import org.eclipse.californium.core.coap.Request;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class Utils {
	
	
	public static boolean isJSONValid(String test) {
	    try {
	        new JSONObject(test);
	    } catch (JSONException ex) {
	        // edited, to include @Arthur's comment
	        // e.g. in case JSONArray is valid as well...
	        try {
	            new JSONArray(test);
	        } catch (JSONException ex1) {
	            return false;
	        }
	    }
	    return true;
	}
	

	/*
	 * Instantiates a new request based on a string describing a method.
	 * 
	 * @return A new request object, or null if method not recognized
	 */
	public static Request newRequest(String method) {
		if (method.equalsIgnoreCase("GET")) {
			return Request.newGet();
		} else if (method.equalsIgnoreCase("POST")) {
			return Request.newPost();
		} else if (method.equalsIgnoreCase("PUT")) {
			return Request.newPut();
		} else if (method.equalsIgnoreCase("DELETE")) {
			return Request.newDelete();
		} else if (method.equalsIgnoreCase("DISCOVER")) {
			return Request.newGet();
		} else if (method.equalsIgnoreCase("OBSERVE")) {
			Request request = Request.newGet();
			request.setObserve();
			return request;
		} else {
			System.err.println("Unknown method: " + method);
			return null;
		}
	}
}
