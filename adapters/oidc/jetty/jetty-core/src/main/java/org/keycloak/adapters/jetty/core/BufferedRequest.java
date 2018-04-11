package org.keycloak.adapters.jetty.core;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.security.Principal;
import java.util.Collection;
import java.util.Enumeration;
import java.util.EventListener;
import java.util.Locale;
import java.util.Map;

import javax.servlet.AsyncContext;
import javax.servlet.DispatcherType;
import javax.servlet.ReadListener;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpUpgradeHandler;
import javax.servlet.http.Part;

import org.eclipse.jetty.http.HttpFields;
import org.eclipse.jetty.http.HttpMethod;
import org.eclipse.jetty.http.HttpURI;
import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.server.Authentication;
import org.eclipse.jetty.server.HttpChannel;
import org.eclipse.jetty.server.HttpChannelState;
import org.eclipse.jetty.server.HttpInput;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.SessionManager;
import org.eclipse.jetty.server.UserIdentity;
import org.eclipse.jetty.server.UserIdentity.Scope;
import org.eclipse.jetty.server.handler.ContextHandler.Context;
import org.eclipse.jetty.util.Attributes;
import org.eclipse.jetty.util.MultiMap;
import org.jboss.logging.Logger;

public class BufferedRequest extends Request {
	protected static final org.jboss.logging.Logger log = Logger.getLogger(BufferedRequest.class);	
	private String body;
	private ServletInputStream origInputStream;
	private Request original;
	private boolean buffered = false;
	public BufferedRequest(Request req)
	{
		super(req.getHttpChannel(),req.getHttpInput());
		original = req;
		buffered = false;
		body ="";
	}
    
	public void moveRequestBodyToBuffer()
	{
		if(!buffered)
		{
		    StringBuilder stringBuilder = new StringBuilder();  
		    BufferedReader bufferedReader = null;  
		    try {  
		    	origInputStream = original.getInputStream(); 
	
		        if (origInputStream != null) {  
		            bufferedReader = new BufferedReader(new InputStreamReader(origInputStream));  
	
		            char[] charBuffer = new char[1024];  
		            int bytesRead = -1;  
	
		            while ((bytesRead = bufferedReader.read(charBuffer)) > 0) {  
		                stringBuilder.append(charBuffer, 0, bytesRead);  
		            }  
		        } else {  
		            stringBuilder.append("");  
		        }  
		    } catch (IOException ex) {  
		        log.error("Error reading request");
		    } finally {  
		        if (bufferedReader != null) {  
		            try {  
		                bufferedReader.close();  
		            } catch (IOException ex) {  
		            	log.error("Error closing request reader");
		            }  
		        }  
		    }  
		    body = stringBuilder.toString();
		    buffered = true;
		}
	}
	@Override
	public ServletInputStream getInputStream() throws IOException
	{
		if(buffered)
		{
		    final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(body.getBytes());
	
		    ServletInputStream inputStream = new ServletInputStream() {  
	
		        public int read () throws IOException {  
		            return byteArrayInputStream.read();  
		        }  
		        
		        public void setReadListener(ReadListener listener) {
		        	origInputStream.setReadListener(listener);
		        }	        
	
		        public int available() {
		            return byteArrayInputStream.available();
		        }
	
	
		        public int read(byte[] buf, int off, int len) {
		            return byteArrayInputStream.read(buf, off, len);
		        }
	
		        public boolean isFinished() {
		            return (byteArrayInputStream.available() <= 0);
		        }
	
		        public boolean isReady() {
		            return (byteArrayInputStream.available() > 0);
		        }	        
		    };
	
		    return inputStream;	
		}
		else
		{
			return original.getInputStream();
		}
	}

	@Override
	public void addEventListener(EventListener listener) {
		original.addEventListener(listener);
	}

	@Override
	public boolean authenticate(HttpServletResponse response) throws IOException, ServletException {
		return original.authenticate(response);
	}

	@Override
	public String changeSessionId() {
		return original.changeSessionId();
	}

	@Override
	public void extractFormParameters(MultiMap<String> arg0) {
		original.extractFormParameters(arg0);
	}

	@Override
	public void extractParameters() {
		original.extractParameters();
	}

	@Override
	public AsyncContext getAsyncContext() {
		return original.getAsyncContext();
	}

	@Override
	public Object getAttribute(String name) {
		return original.getAttribute(name);
	}

	@Override
	public Enumeration<String> getAttributeNames() {
		return original.getAttributeNames();
	}

	@Override
	public Attributes getAttributes() {
		return original.getAttributes();
	}

	@Override
	public String getAuthType() {
		return original.getAuthType();
	}

	@Override
	public Authentication getAuthentication() {
		return original.getAuthentication();
	}

	@Override
	public String getCharacterEncoding() {
		return original.getCharacterEncoding();
	}

	@Override
	public int getContentLength() {
		return original.getContentLength();
	}

	@Override
	public long getContentLengthLong() {
		return original.getContentLengthLong();
	}

	@Override
	public long getContentRead() {
		return original.getContentRead();
	}

	@Override
	public String getContentType() {
		return original.getContentType();
	}

	@Override
	public Context getContext() {
		return original.getContext();
	}

	@Override
	public String getContextPath() {
		return original.getContextPath();
	}

	@Override
	public Cookie[] getCookies() {
		return original.getCookies();
	}

	@Override
	public long getDateHeader(String name) {
		return original.getDateHeader(name);
	}

	@Override
	public DispatcherType getDispatcherType() {
		return original.getDispatcherType();
	}

	@Override
	public String getHeader(String name) {
		return original.getHeader(name);
	}

	@Override
	public Enumeration<String> getHeaderNames() {
		return original.getHeaderNames();
	}

	@Override
	public Enumeration<String> getHeaders(String name) {
		return original.getHeaders(name);
	}

	@Override
	public HttpChannel<?> getHttpChannel() {
		return original.getHttpChannel();
	}

	@Override
	public HttpChannelState getHttpChannelState() {
		return original.getHttpChannelState();
	}

	@Override
	public HttpFields getHttpFields() {
		return original.getHttpFields();
	}

	@Override
	public HttpInput<?> getHttpInput() {
		return original.getHttpInput();
	}

	@Override
	public HttpVersion getHttpVersion() {
		return original.getHttpVersion();
	}

	@Override
	public int getInputState() {
		return original.getInputState();
	}

	@Override
	public int getIntHeader(String name) {
		return original.getIntHeader(name);
	}

	@Override
	public String getLocalAddr() {
		return original.getLocalAddr();
	}

	@Override
	public String getLocalName() {
		return original.getLocalName();
	}

	@Override
	public int getLocalPort() {
		return original.getLocalPort();
	}

	@Override
	public Locale getLocale() {
		return original.getLocale();
	}

	@Override
	public Enumeration<Locale> getLocales() {
		return original.getLocales();
	}

	@Override
	public String getMethod() {
		return original.getMethod();
	}

	@Override
	public String getParameter(String name) {
		return original.getParameter(name);
	}

	@Override
	public Map<String, String[]> getParameterMap() {
		return original.getParameterMap();
	}

	@Override
	public Enumeration<String> getParameterNames() {
		return original.getParameterNames();
	}

	@Override
	public String[] getParameterValues(String name) {
		return original.getParameterValues(name);
	}

	@Override
	public Part getPart(String name) throws IOException, ServletException {
		return original.getPart(name);
	}

	@Override
	public Collection<Part> getParts() throws IOException, ServletException {
		return original.getParts();
	}

	@Override
	public String getPathInfo() {
		return original.getPathInfo();
	}

	@Override
	public String getPathTranslated() {
		return original.getPathTranslated();
	}

	@Override
	public String getProtocol() {
		return original.getProtocol();
	}

	@Override
	public String getQueryEncoding() {
		return original.getQueryEncoding();
	}

	@Override
	public MultiMap<String> getQueryParameters() {
		return original.getQueryParameters();
	}

	@Override
	public String getQueryString() {
		return original.getQueryString();
	}

	@Override
	public BufferedReader getReader() throws IOException {
		return original.getReader();
	}

	@Override
	public String getRealPath(String path) {
		return original.getRealPath(path);
	}

	@Override
	public String getRemoteAddr() {
		return original.getRemoteAddr();
	}

	@Override
	public String getRemoteHost() {
		return original.getRemoteHost();
	}

	@Override
	public InetSocketAddress getRemoteInetSocketAddress() {
		return original.getRemoteInetSocketAddress();
	}

	@Override
	public int getRemotePort() {
		return original.getRemotePort();
	}

	@Override
	public String getRemoteUser() {
		return original.getRemoteUser();
	}

	@Override
	public RequestDispatcher getRequestDispatcher(String arg0) {
		return original.getRequestDispatcher(arg0);
	}

	@Override
	public String getRequestURI() {
		return original.getRequestURI();
	}

	@Override
	public StringBuffer getRequestURL() {
		return original.getRequestURL();
	}

	@Override
	public String getRequestedSessionId() {
		return original.getRequestedSessionId();
	}

	@Override
	public UserIdentity getResolvedUserIdentity() {
		return original.getResolvedUserIdentity();
	}

	@Override
	public Response getResponse() {
		return original.getResponse();
	}

	@Override
	public StringBuilder getRootURL() {
		return original.getRootURL();
	}

	@Override
	public String getScheme() {
		return original.getScheme();
	}

	@Override
	public String getServerName() {
		return original.getServerName();
	}

	@Override
	public int getServerPort() {
		return original.getServerPort();
	}

	@Override
	public ServletContext getServletContext() {
		return original.getServletContext();
	}

	@Override
	public String getServletName() {
		return original.getServletName();
	}

	@Override
	public String getServletPath() {
		return original.getServletPath();
	}

	@Override
	public ServletResponse getServletResponse() {
		return original.getServletResponse();
	}

	@Override
	public HttpSession getSession() {
		return original.getSession();
	}

	@Override
	public HttpSession getSession(boolean create) {
		return original.getSession(create);
	}

	@Override
	public SessionManager getSessionManager() {
		return original.getSessionManager();
	}

	@Override
	public long getTimeStamp() {
		return original.getTimeStamp();
	}

	@Override
	public HttpURI getUri() {
		return original.getUri();
	}

	@Override
	public UserIdentity getUserIdentity() {
		return original.getUserIdentity();
	}

	@Override
	public Scope getUserIdentityScope() {
		return original.getUserIdentityScope();
	}

	@Override
	public Principal getUserPrincipal() {
		return original.getUserPrincipal();
	}

	@Override
	public boolean isAsyncStarted() {
		return original.isAsyncStarted();
	}

	@Override
	public boolean isAsyncSupported() {
		return original.isAsyncSupported();
	}

	@Override
	public boolean isHandled() {
		return original.isHandled();
	}

	@Override
	public boolean isHead() {
		return original.isHead();
	}

	@Override
	public boolean isRequestedSessionIdFromCookie() {
		return original.isRequestedSessionIdFromCookie();
	}

	@Override
	public boolean isRequestedSessionIdFromURL() {
		return original.isRequestedSessionIdFromURL();
	}

	@Override
	public boolean isRequestedSessionIdFromUrl() {
		return original.isRequestedSessionIdFromUrl();
	}

	@Override
	public boolean isRequestedSessionIdValid() {
		return original.isRequestedSessionIdValid();
	}

	@Override
	public boolean isSecure() {
		return original.isSecure();
	}

	@Override
	public boolean isUserInRole(String role) {
		return original.isUserInRole(role);
	}

	@Override
	public void login(String username, String password) throws ServletException {
		original.login(username, password);
	}

	@Override
	public void logout() throws ServletException {
		original.logout();
	}

	@Override
	public void mergeQueryParameters(String arg0, boolean arg1) {
		original.mergeQueryParameters(arg0, arg1);
	}

	@Override
	public HttpSession recoverNewSession(Object key) {
		return original.recoverNewSession(key);
	}

	@Override
	public void removeAttribute(String arg0) {
		original.removeAttribute(arg0);
	}

	@Override
	public void removeEventListener(EventListener listener) {
		original.removeEventListener(listener);
	}

	@Override
	public void resetParameters() {
		original.resetParameters();
	}

	@Override
	public void saveNewSession(Object key, HttpSession session) {
		original.saveNewSession(key, session);
	}

	@Override
	public void setAsyncSupported(boolean supported) {
		original.setAsyncSupported(supported);
	}

	@Override
	public void setAttribute(String arg0, Object arg1) {
		original.setAttribute(arg0, arg1);
	}

	@Override
	public void setAttributes(Attributes attributes) {
		original.setAttributes(attributes);
	}

	@Override
	public void setAuthentication(Authentication authentication) {
		original.setAuthentication(authentication);
	}

	@Override
	public void setCharacterEncoding(String arg0) throws UnsupportedEncodingException {
		original.setCharacterEncoding(arg0);
	}

	@Override
	public void setCharacterEncodingUnchecked(String encoding) {
		original.setCharacterEncodingUnchecked(encoding);
	}

	@Override
	public void setContentParameters(MultiMap<String> contentParameters) {
		original.setContentParameters(contentParameters);
	}

	@Override
	public void setContentType(String contentType) {
		original.setContentType(contentType);
	}

	@Override
	public void setContext(Context context) {
		original.setContext(context);
	}

	@Override
	public void setContextPath(String contextPath) {
		original.setContextPath(contextPath);
	}

	@Override
	public void setCookies(Cookie[] cookies) {
		original.setCookies(cookies);
	}

	@Override
	public void setDispatcherType(DispatcherType type) {
		original.setDispatcherType(type);
	}

	@Override
	public void setHandled(boolean h) {
		original.setHandled(h);
	}

	@Override
	public void setHttpVersion(HttpVersion version) {
		original.setHttpVersion(version);
	}

	@Override
	public void setMethod(HttpMethod httpMethod, String method) {
		original.setMethod(httpMethod, method);
	}

	@Override
	public void setPathInfo(String pathInfo) {
		original.setPathInfo(pathInfo);
	}

	@Override
	public void setQueryEncoding(String queryEncoding) {
		original.setQueryEncoding(queryEncoding);
	}

	@Override
	public void setQueryParameters(MultiMap<String> queryParameters) {
		original.setQueryParameters(queryParameters);
	}

	@Override
	public void setQueryString(String queryString) {
		original.setQueryString(queryString);
	}

	@Override
	public void setRemoteAddr(InetSocketAddress addr) {
		original.setRemoteAddr(addr);
	}

	@Override
	public void setRequestURI(String requestURI) {
		original.setRequestURI(requestURI);
	}

	@Override
	public void setRequestedSessionId(String requestedSessionId) {
		original.setRequestedSessionId(requestedSessionId);
	}

	@Override
	public void setRequestedSessionIdFromCookie(boolean requestedSessionIdCookie) {
		original.setRequestedSessionIdFromCookie(requestedSessionIdCookie);
	}

	@Override
	public void setScheme(String scheme) {
		original.setScheme(scheme);
	}

	@Override
	public void setSecure(boolean secure) {
		original.setSecure(secure);
	}

	@Override
	public void setServerName(String host) {
		original.setServerName(host);
	}

	@Override
	public void setServerPort(int port) {
		original.setServerPort(port);
	}

	@Override
	public void setServletPath(String servletPath) {
		original.setServletPath(servletPath);
	}

	@Override
	public void setSession(HttpSession session) {
		original.setSession(session);
	}

	@Override
	public void setSessionManager(SessionManager sessionManager) {
		original.setSessionManager(sessionManager);
	}

	@Override
	public void setTimeStamp(long ts) {
		original.setTimeStamp(ts);
	}

	@Override
	public void setUri(HttpURI uri) {
		original.setUri(uri);
	}

	@Override
	public void setUserIdentityScope(Scope scope) {
		original.setUserIdentityScope(scope);
	}

	@Override
	public AsyncContext startAsync() throws IllegalStateException {
		return original.startAsync();
	}

	@Override
	public AsyncContext startAsync(ServletRequest servletRequest, ServletResponse servletResponse)
			throws IllegalStateException {
		return original.startAsync(servletRequest, servletResponse);
	}

	@Override
	public boolean takeNewContext() {
		return original.takeNewContext();
	}

	@Override
	public String toString() {
		return original.toString();
	}

	@Override
	public <T extends HttpUpgradeHandler> T upgrade(Class<T> arg0) throws IOException, ServletException {
		return original.upgrade(arg0);
	}
}
