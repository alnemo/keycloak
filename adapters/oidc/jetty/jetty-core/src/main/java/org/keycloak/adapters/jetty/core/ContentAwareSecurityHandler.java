package org.keycloak.adapters.jetty.core;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.server.Request;

public class ContentAwareSecurityHandler extends ConstraintSecurityHandler {

    @Override
    public void handle(String pathInContext, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
    {
    	if (request instanceof Request)
    	{
    		BufferedRequest wrappedRequest = new BufferedRequest((Request) request);
    		super.handle(pathInContext, baseRequest, wrappedRequest, response);
    	}
    	else 
    	{
    		super.handle(pathInContext, baseRequest, request, response);
    	}
    }

}
