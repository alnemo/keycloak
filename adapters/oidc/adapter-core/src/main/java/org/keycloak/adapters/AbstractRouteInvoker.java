package org.keycloak.adapters;

import java.util.Map;

/**
 * Abstraction for invoking camel routes without adding dependency
 *
 */
public interface AbstractRouteInvoker {
	
	public String callRouteGetProperty(String route, Map<String,Object> headers, Map<String,Object> properties, String propertyName);

	public String callRouteGetBody(String route, Map<String,Object> headers, Map<String,Object> properties);	
}
