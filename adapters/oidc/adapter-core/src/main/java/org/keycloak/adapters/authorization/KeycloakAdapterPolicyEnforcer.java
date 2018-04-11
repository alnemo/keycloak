/*
 *  Copyright 2016 Red Hat, Inc. and/or its affiliates
 *  and other contributors as indicated by the @author tags.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.keycloak.adapters.authorization;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.jboss.logging.Logger;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.OIDCHttpFacade;
import org.keycloak.adapters.rotation.AdapterRSATokenVerifier;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.adapters.spi.HttpFacade.Request;
import org.keycloak.authorization.client.AuthorizationDeniedException;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.representation.AuthorizationRequest;
import org.keycloak.authorization.client.representation.AuthorizationResponse;
import org.keycloak.authorization.client.representation.EntitlementRequest;
import org.keycloak.authorization.client.representation.EntitlementResponse;
import org.keycloak.authorization.client.representation.PermissionRequest;
import org.keycloak.authorization.client.representation.PermissionResponse;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.adapters.config.PolicyEnforcerConfig.ExtractedValueConfig;
import org.keycloak.representations.adapters.config.PolicyEnforcerConfig.PathConfig;
import org.keycloak.representations.idm.authorization.Permission;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class KeycloakAdapterPolicyEnforcer extends AbstractPolicyEnforcer {

    private static Logger LOGGER = Logger.getLogger(KeycloakAdapterPolicyEnforcer.class);

    public KeycloakAdapterPolicyEnforcer(PolicyEnforcer policyEnforcer) {
        super(policyEnforcer);
    }

    @Override
    protected boolean isAuthorized(PathConfig pathConfig, Set<String> requiredScopes, AccessToken accessToken, OIDCHttpFacade httpFacade) {
        AccessToken original = accessToken;

        if (super.isAuthorized(pathConfig, requiredScopes, accessToken, httpFacade)) {
            return true;
        }

        accessToken = requestAuthorizationToken(pathConfig, requiredScopes, httpFacade);

        if (accessToken == null) {
            return false;
        }

        AccessToken.Authorization authorization = original.getAuthorization();

        if (authorization == null) {
            authorization = new AccessToken.Authorization();
            authorization.setPermissions(new ArrayList<Permission>());
        }

        AccessToken.Authorization newAuthorization = accessToken.getAuthorization();

        if (newAuthorization != null) {
            authorization.getPermissions().addAll(newAuthorization.getPermissions());
        }

        original.setAuthorization(authorization);

        return super.isAuthorized(pathConfig, requiredScopes, accessToken, httpFacade);
    }

    @Override
    protected boolean challenge(PathConfig pathConfig, Set<String> requiredScopes, OIDCHttpFacade facade) {
        handleAccessDenied(facade);
        return true;
    }

    @Override
    protected void handleAccessDenied(OIDCHttpFacade facade) {
        String accessDeniedPath = getEnforcerConfig().getOnDenyRedirectTo();
        HttpFacade.Response response = facade.getResponse();

        if (accessDeniedPath != null) {
            response.setStatus(302);
            response.setHeader("Location", accessDeniedPath);
        } else {
            response.sendError(403);
        }
    }

    private AccessToken requestAuthorizationToken(PathConfig pathConfig, Set<String> requiredScopes, OIDCHttpFacade httpFacade) {
        try {
            String accessToken = httpFacade.getSecurityContext().getTokenString();
            AuthzClient authzClient = getAuthzClient();
            KeycloakDeployment deployment = getPolicyEnforcer().getDeployment();

            if (getEnforcerConfig().getUserManagedAccess() != null) {
                LOGGER.debug("Obtaining authorization for authenticated user.");
                PermissionRequest permissionRequest = new PermissionRequest();

                permissionRequest.setResourceSetId(pathConfig.getId());
                permissionRequest.setResourceSetUri(httpFacade.getRequest().getURI());
                permissionRequest.setScopes(requiredScopes);
                permissionRequest.setAttributes(extractRequestAttributes(deployment,httpFacade));
                PermissionResponse permissionResponse = authzClient.protection().permission().forResource(permissionRequest);
                AuthorizationRequest authzRequest = new AuthorizationRequest(permissionResponse.getTicket());
                AuthorizationResponse authzResponse = authzClient.authorization(accessToken).authorize(authzRequest);

                if (authzResponse != null) {
                    return AdapterRSATokenVerifier.verifyToken(authzResponse.getRpt(), deployment);
                }

                return null;
            } else {
                LOGGER.debug("Obtaining entitlements for authenticated user.");
                AccessToken token = httpFacade.getSecurityContext().getToken();

                if (token.getAuthorization() == null) {
                    EntitlementResponse authzResponse = authzClient.entitlement(accessToken).getAll(authzClient.getConfiguration().getClientId());
                    return AdapterRSATokenVerifier.verifyToken(authzResponse.getRpt(), deployment);
                } else {
                    EntitlementRequest request = new EntitlementRequest();
                    PermissionRequest permissionRequest = new PermissionRequest();
                    permissionRequest.setResourceSetId(pathConfig.getId());
                    permissionRequest.setResourceSetName(pathConfig.getName());
                    permissionRequest.setResourceSetUri(httpFacade.getRequest().getURI());
                    permissionRequest.setScopes(new HashSet<>(pathConfig.getScopes()));
                    permissionRequest.setAttributes(extractRequestAttributes(deployment,httpFacade));
                    LOGGER.debugf("Sending entitlements request: resource_set_id [%s], resource_set_name [%s], scopes [%s].", permissionRequest.getResourceSetId(), permissionRequest.getResourceSetName(), permissionRequest.getScopes());
                    request.addPermission(permissionRequest);
                    EntitlementResponse authzResponse = authzClient.entitlement(accessToken).get(authzClient.getConfiguration().getClientId(), request);
                    return AdapterRSATokenVerifier.verifyToken(authzResponse.getRpt(), deployment);
                }
            }
        } catch (AuthorizationDeniedException e) {
            LOGGER.debug("Authorization denied", e);
            return null;
        } catch (Exception e) {
            throw new RuntimeException("Unexpected error during authorization request.", e);
        }
    }
    
    private Map<String,String> extractRequestAttributes(KeycloakDeployment deployment, OIDCHttpFacade httpFacade)
    {
    	Map<String,String> attributes = new HashMap<String,String>();
    	Map<String,List<ExtractedValueConfig>> config = deployment.getExtractedAttributes().get(httpFacade.getRequest().getMethod());
    	if(config == null)
    	{
    		return attributes;
    	}
    	String targetUri = httpFacade.getRequest().getURI();
    	int patternStartIndex = targetUri.indexOf("rest");
    	int patternEndIndex = targetUri.indexOf("?");
    	if(patternEndIndex != -1)
    	{
    		targetUri = targetUri.substring(patternStartIndex+4,patternEndIndex);
    	}
    	else
    	{
    		targetUri = targetUri.substring(patternStartIndex+4);
    	}
    	boolean matchFound = false;
    	List<ExtractedValueConfig> extractValues = null;
    	for(String expectedUri: config.keySet())
    	{
	       	 if (this.pathMatcher.isTemplate(expectedUri)) 
	       	 {
	       		  String templateUri = this.pathMatcher.buildUriFromTemplate(expectedUri, targetUri);
		          if (templateUri != null) 
		          {
			          if (this.pathMatcher.exactMatch(expectedUri, targetUri, templateUri)) 
			          {
			        	  matchFound = true;
			        	  extractValues = config.get(expectedUri);
			          }
		          }
	       	 } 
	       	 else
	       	 {
	       		if (this.pathMatcher.exactMatch(expectedUri, targetUri, expectedUri))
	       		{
	       			matchFound = true;
	       			extractValues = config.get(expectedUri);
	       		}
	       	 }
	       	 if(matchFound)
	       	 {
	       		 break;
	       	 }
    	}
    	if(matchFound)
    	{
    		for(ExtractedValueConfig valueConfig: extractValues)
    		{
    			switch (valueConfig.getSource())
    			{
	    			case HEADER: attributes.put(valueConfig.getName(),httpFacade.getRequest().getHeader(valueConfig.getLocation()));
	    				break;
	    			case QUERY: attributes.put(valueConfig.getName(),httpFacade.getRequest().getQueryParamValue(valueConfig.getLocation()));
	    				break;
	    			case BODY: attributes.put(valueConfig.getName(), getBodyAttribute(httpFacade, valueConfig.getType(), valueConfig.getLocation()));
	    				break;
					case HTTPAPI: attributes.put(valueConfig.getName(), getAPIAttribute(httpFacade, deployment, valueConfig));
						break;
					case ROUTE: attributes.put(valueConfig.getName(), getRouteAttribute(httpFacade, deployment, valueConfig));
						break;
					default: LOGGER.warn("Unrecognized extracted attribute source");
						break;
	    					
    			}
    		}
    	}	
    	return attributes;
    }
    
    private String getBodyAttribute(OIDCHttpFacade httpFacade, String contentType, String location)
    {
    	String value = "";
    	Request req = httpFacade.getRequest();
    	if(req.getHeader("Content-Type").startsWith(contentType))
    	{
    		if("application/json".equals(contentType))
    		{
    			try {
    				//only work with buffered request body to avoid consuming it
    				java.lang.reflect.Method method = httpFacade.getClass().getMethod("bufferRequest");
    				method.invoke(httpFacade);
    	    		value = getJSONBodyAttribute(req.getInputStream(), location);
				} catch (NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
					LOGGER.warn("Cannot read body attribute from unbuffered request");
				}
    		}
    		else
    		{
    			LOGGER.warnf("Unimplemented content type for attribute extraction [%s]", contentType);
    		}		
    	}
		return value;
    }
    
    private String getJSONBodyAttribute(InputStream bodyStream, String path)
    {   	    
    	String value = "";	 	
		ObjectMapper objectMapper = new ObjectMapper();  
		JsonNode root;
		try {
			root = objectMapper.readTree(bodyStream);		
    		value = root.at(path).asText();
		} 
		catch (IOException e) 
		{
			LOGGER.error("Failed to extract attributes from JSON request");
		}
		return value;
    }
    
    private String getRouteAttribute(OIDCHttpFacade httpFacade, KeycloakDeployment deployment, ExtractedValueConfig valueConfig)
    {
    	Map<String,Object> headers = resolvePlaceholders(httpFacade, valueConfig.getHeaders());
    	Map<String,Object> properties = resolvePlaceholders(httpFacade, valueConfig.getProperties());    	
    	String body = deployment.getRouteInvoker().callRouteGetBody(valueConfig.getEndpoint(), headers, properties);
    	
		ObjectMapper objectMapper = new ObjectMapper();  
		JsonNode root;
        try 
        {
			root = objectMapper.readTree(body);		
			String value = root.at(valueConfig.getLocation()).asText();
			return value;
        }
        catch(UnsupportedOperationException | IOException e)
        {
        	LOGGER.error("Failed to extract attributes from route response");
        	return null;
        }
    	
    }
    private String getAPIAttribute(OIDCHttpFacade httpFacade, KeycloakDeployment deployment, ExtractedValueConfig valueConfig)
    {    	
        HttpClient client = deployment.getClient();
        URI uri = URI.create(resolvePlaceholders(httpFacade, valueConfig.getEndpoint()));
        HttpGet get = new HttpGet(uri);
        Map<String, String> headers = valueConfig.getHeaders();
        String value = "";
        if(headers != null && !headers.isEmpty())
        {
        	for(Map.Entry<String, String> entry: headers.entrySet())
        	{
        		get.setHeader(entry.getKey(), resolvePlaceholders(httpFacade,entry.getValue()));
        	}
        }
        HttpResponse response;
		try 
		{
			response = client.execute(get);
		} 
		catch (IOException e) 
		{
			LOGGER.error("Failed to get attribute from HTTP API");
			return null;
		} 
        int status = response.getStatusLine().getStatusCode();
        if(status != 200)
        {
        	LOGGER.warnf("While retrieving attribute HTTP API responds with status: %d", status);
        	return null;
        }
        HttpEntity entity = response.getEntity();

        if (entity == null) 
        {
            return null;
        }
        try 
        {
			InputStream is = entity.getContent();
			ObjectMapper objectMapper = new ObjectMapper();  
			JsonNode root;
			root = objectMapper.readTree(is);		
    		value = root.at(valueConfig.getLocation()).asText();
    		return value;
		} 
        catch (UnsupportedOperationException | IOException e) 
        {
        	LOGGER.error("Failed to get attribute from HTTP API");
        	return null;
		}    	
    }
    
    private Map<String,Object> resolvePlaceholders(OIDCHttpFacade httpFacade, Map<String,String> config)
    {
    	Map<String,Object> result = new HashMap<String,Object>();
    	for(Map.Entry<String, String> entry: config.entrySet())
    	{
    		result.put(entry.getKey(), resolvePlaceholders(httpFacade, entry.getValue()));
    	}  	
		return result; 
    }

    private static final String bodyParameterPlaceholder = "{$body";
    private static final String headerParameterPlaceholder = "{$header.";    
    private static final String queryParameterPlaceholder = "{$query.";  
    private static final String tokenParameterPlaceholder = "{$token."; 
    private static final String pathParameterPlaceholder = "{$path."; 
    
    private String resolvePlaceholders(OIDCHttpFacade httpFacade, String original)
    {
    	int patternStart = original.indexOf("{$");
    	if(patternStart == -1)
    	{
    		return original;
    	}
    	
    	int patternEnd = original.indexOf("}", patternStart);
    	String placeholder = original.substring(patternStart, patternEnd+1);
    	String replacement = "";
    	
    	if (placeholder.toLowerCase().startsWith(bodyParameterPlaceholder))
    	{
    		String location = placeholder.substring(bodyParameterPlaceholder.length(), placeholder.length()-1);
    		
    		try {
				//only work with buffered request body to avoid consuming it
				java.lang.reflect.Method method = httpFacade.getClass().getMethod("bufferRequest");
				method.invoke(httpFacade);
				Request req = httpFacade.getRequest();
				replacement = getJSONBodyAttribute(req.getInputStream(), location);
			} catch (NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
				LOGGER.warn("Cannot read body attribute from unbuffered request");
			}
    	}
    	if (placeholder.toLowerCase().startsWith(headerParameterPlaceholder))
    	{
    		String header = placeholder.substring(headerParameterPlaceholder.length(), placeholder.length()-1);
    		replacement = httpFacade.getRequest().getHeader(header);
    	}
    	
    	if (placeholder.toLowerCase().startsWith(queryParameterPlaceholder))
    	{
    		String query = placeholder.substring(queryParameterPlaceholder.length(), placeholder.length()-1);
    		replacement = httpFacade.getRequest().getQueryParamValue(query);
    	}
    	
    	if (placeholder.toLowerCase().startsWith(tokenParameterPlaceholder))
    	{
    		String claim = placeholder.substring(tokenParameterPlaceholder.length(), placeholder.length()-1);
    		Object value = httpFacade.getSecurityContext().getToken().getOtherClaims().get(claim);
    		if(value != null)
    		{
    			replacement = value.toString();
    		}
    		else
    		{
    			replacement = "";
    		}
    	}
    	
    	if (placeholder.toLowerCase().startsWith(pathParameterPlaceholder))
    	{
    		Integer part = Integer.valueOf(placeholder.substring(pathParameterPlaceholder.length(), placeholder.length()-1));
    		String uri = httpFacade.getRequest().getURI();
    		String[] parts = uri.split("[/?]");

    		if(part != null && parts.length > part)
    		{
    			replacement = parts[part];
    		}
    		else
    		{
    			replacement = "";
    		}
    	}
    	
    	if (replacement == null)
    	{
    		replacement = "";
    	}
    	
    	String result = original.replace(placeholder, replacement);
    	
    	if(result.indexOf("{$") == -1)
    	{
    		return result;
    	}
    	else
    	{
    		return resolvePlaceholders(httpFacade, result);
    	}	
    }
}
