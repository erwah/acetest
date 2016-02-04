package se.wahlstromstekniska.acetest.resourceserver;

import java.nio.charset.StandardCharsets;

import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.json.JSONObject;


public class TemperatureResponse {
	
	private double temperature = 0;
	
	public TemperatureResponse(double temperature) {
		this.temperature = temperature;
	}

	public TemperatureResponse(byte[] payload, int contentFormat) throws Exception {
		if(contentFormat == MediaTypeRegistry.APPLICATION_JSON) {
			String json = new String(payload, StandardCharsets.UTF_8);
			JSONObject obj = new JSONObject(json);
			setTemperature(obj.getDouble("temperature"));
		}
		else {
			throw new Exception("Not implemented yet");
		}
	}
	
	public byte[] toPayload(int contentFormat) {

		if(contentFormat == MediaTypeRegistry.APPLICATION_JSON) {
			String json = "{"
					+ "\n\t\"temperature\" : " + temperature
					+ "\n}";
			
			return json.getBytes();
		}
		else {
			return "not implemented yet".getBytes();
		}
	}

	public double getTemperature() {
		return temperature;
	}

	public void setTemperature(double temperature) {
		this.temperature = temperature;
	}

	@Override
	public String toString() {
		return "TemperatureResponse [temperature=" + temperature + "]";
	}
		
}
