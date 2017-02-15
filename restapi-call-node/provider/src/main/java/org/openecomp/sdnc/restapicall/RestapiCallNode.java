/*-
 * ============LICENSE_START=======================================================
 * openECOMP : SDN-C
 * ================================================================================
 * Copyright (C) 2017 AT&T Intellectual Property. All rights
 *             reserved.
 * ================================================================================
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ============LICENSE_END=========================================================
 */

package org.openecomp.sdnc.restapicall;

import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.ws.rs.core.EntityTag;
import javax.ws.rs.core.MultivaluedMap;

import org.openecomp.sdnc.sli.SvcLogicContext;
import org.openecomp.sdnc.sli.SvcLogicException;
import org.openecomp.sdnc.sli.SvcLogicJavaPlugin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.client.config.ClientConfig;
import com.sun.jersey.api.client.config.DefaultClientConfig;
import com.sun.jersey.api.client.filter.HTTPBasicAuthFilter;
import com.sun.jersey.client.urlconnection.HTTPSProperties;

public class RestapiCallNode implements SvcLogicJavaPlugin {

	private static final Logger log = LoggerFactory.getLogger(RestapiCallNode.class);

	private String uebServers;
	private String defaultUebTemplateFileName = "/opt/bvc/restapi/templates/default-ueb-message.json";

	public void sendRequest(Map<String, String> paramMap, SvcLogicContext ctx) throws SvcLogicException {
		HttpResponse r = null;
		try {
			Param p = getParameters(paramMap);

			String pp = p.responsePrefix != null ? p.responsePrefix + '.' : "";

			String req = null;
			if (p.templateFileName != null) {
				String reqTemplate = readFile(p.templateFileName);
				req = buildXmlJsonRequest(ctx, reqTemplate, p.format);
			}
			r = sendHttpRequest(req, p);
			setResponseStatus(ctx, p.responsePrefix, r);

			if (r.body != null && r.body.trim().length() > 0) {
				ctx.setAttribute(pp + "httpResponse", r.body);

				if (p.convertResponse) {
					Map<String, String> mm = null;
					if (p.format == Format.XML)
						mm = XmlParser.convertToProperties(r.body, p.listNameList);
					else if (p.format == Format.JSON)
						mm = JsonParser.convertToProperties(r.body);

					if (mm != null)
						for (String key : mm.keySet())
							ctx.setAttribute(pp + key, mm.get(key));
				}
			}
		} catch (Exception e) {
			log.error("Error sending the request: " + e.getMessage(), e);

			r = new HttpResponse();
			r.code = 500;
			r.message = e.getMessage();
			String prefix = parseParam(paramMap, "responsePrefix", false, null);
			setResponseStatus(ctx, prefix, r);
		}

		if (r != null && r.code >= 300)
			throw new SvcLogicException(String.valueOf(r.code) + ": " + r.message);
	}

	private Param getParameters(Map<String, String> paramMap) throws SvcLogicException {
		Param p = new Param();
		p.templateFileName = parseParam(paramMap, "templateFileName", false, null);
		p.restapiUrl = parseParam(paramMap, "restapiUrl", true, null);
		p.restapiUser = parseParam(paramMap, "restapiUser", true, null);
		p.restapiPassword = parseParam(paramMap, "restapiPassword", true, null);
		p.format = Format.fromString(parseParam(paramMap, "format", false, "json"));
		p.httpMethod = HttpMethod.fromString(parseParam(paramMap, "httpMethod", false, "post"));
		p.responsePrefix = parseParam(paramMap, "responsePrefix", false, null);
		p.listNameList = getListNameList(paramMap);
		String skipSendingStr = paramMap.get("skipSending");
		p.skipSending = skipSendingStr != null && skipSendingStr.equalsIgnoreCase("true");
		p.convertResponse = Boolean.valueOf(parseParam(paramMap, "convertResponse", false, "true"));
		p.trustStoreFileName = parseParam(paramMap, "trustStoreFileName", false, null);
		p.trustStorePassword = parseParam(paramMap, "trustStorePassword", false, null);
		p.keyStoreFileName = parseParam(paramMap, "keyStoreFileName", false, null);
		p.keyStorePassword = parseParam(paramMap, "keyStorePassword", false, null);
		p.ssl = p.trustStoreFileName != null && p.trustStorePassword != null && p.keyStoreFileName != null &&
		        p.keyStorePassword != null;
		return p;
	}

	private Set<String> getListNameList(Map<String, String> paramMap) {
		Set<String> ll = new HashSet<String>();
		for (String key : paramMap.keySet())
			if (key.startsWith("listName"))
				ll.add(paramMap.get(key));
		return ll;
	}

	private String parseParam(Map<String, String> paramMap, String name, boolean required, String def)
	        throws SvcLogicException {
		String s = paramMap.get(name);

		if (s == null || s.trim().length() == 0) {
			if (!required)
				return def;
			throw new SvcLogicException("Parameter " + name + " is required in RestapiCallNode");
		}

		s = s.trim();
		String value = "";
		int i = 0;
		int i1 = s.indexOf('%');
		while (i1 >= 0) {
			int i2 = s.indexOf('%', i1 + 1);
			if (i2 < 0)
				break;

			String varName = s.substring(i1 + 1, i2);
			String varValue = System.getenv(varName);
			if (varValue == null)
				varValue = "%" + varName + "%";

			value += s.substring(i, i1);
			value += varValue;

			i = i2 + 1;
			i1 = s.indexOf('%', i);
		}
		value += s.substring(i);

		log.info("Parameter " + name + ": [" + value + "]");
		return value;
	}

	private static class Param {

		public String templateFileName;
		public String restapiUrl;
		public String restapiUser;
		public String restapiPassword;
		public Format format;
		public HttpMethod httpMethod;
		public String responsePrefix;
		public Set<String> listNameList;
		public boolean skipSending;
		public boolean convertResponse;
		public String keyStoreFileName;
		public String keyStorePassword;
		public String trustStoreFileName;
		public String trustStorePassword;
		public boolean ssl;
	}

	private static enum Format {
		JSON, XML;

		public static Format fromString(String s) {
			if (s == null)
				return null;
			if (s.equalsIgnoreCase("json"))
				return JSON;
			if (s.equalsIgnoreCase("xml"))
				return XML;
			throw new IllegalArgumentException("Invalid value for format: " + s);
		}
	}

	private static enum HttpMethod {
		GET, POST, PUT, DELETE;

		public static HttpMethod fromString(String s) {
			if (s == null)
				return null;
			if (s.equalsIgnoreCase("get"))
				return GET;
			if (s.equalsIgnoreCase("post"))
				return POST;
			if (s.equalsIgnoreCase("put"))
				return PUT;
			if (s.equalsIgnoreCase("delete"))
				return DELETE;
			throw new IllegalArgumentException("Invalid value for HTTP Method: " + s);
		}
	}

	private String buildXmlJsonRequest(SvcLogicContext ctx, String template, Format format) {
		log.info("Building " + format + " started");
		long t1 = System.currentTimeMillis();

		template = expandRepeats(ctx, template, 1);

		Map<String, String> mm = new HashMap<>();
		for (String s : ctx.getAttributeKeySet())
			mm.put(s, ctx.getAttribute(s));

		StringBuilder ss = new StringBuilder();
		int i = 0;
		while (i < template.length()) {
			int i1 = template.indexOf("${", i);
			if (i1 < 0) {
				ss.append(template.substring(i));
				break;
			}

			int i2 = template.indexOf('}', i1 + 2);
			if (i2 < 0)
				throw new RuntimeException("Template error: Matching } not found");

			String var1 = template.substring(i1 + 2, i2);
			String value1 = format == Format.XML ? XmlJsonUtil.getXml(mm, var1) : XmlJsonUtil.getJson(mm, var1);
			// log.info(" " + var1 + ": " + value1);
			if (value1 == null || value1.trim().length() == 0) {
				// delete the whole element (line)
				int i3 = template.lastIndexOf('\n', i1);
				if (i3 < 0)
					i3 = 0;
				int i4 = template.indexOf('\n', i1);
				if (i4 < 0)
					i4 = template.length();

				if (i < i3)
					ss.append(template.substring(i, i3));
				i = i4;
			} else {
				ss.append(template.substring(i, i1)).append(value1);
				i = i2 + 1;
			}
		}

		String req = format == Format.XML
		        ? XmlJsonUtil.removeEmptyStructXml(ss.toString()) : XmlJsonUtil.removeEmptyStructJson(ss.toString());

		if (format == Format.JSON)
			req = XmlJsonUtil.removeLastCommaJson(req);

		long t2 = System.currentTimeMillis();
		log.info("Building " + format + " completed. Time: " + (t2 - t1));

		return req;
	}

	private String expandRepeats(SvcLogicContext ctx, String template, int level) {
		StringBuilder newTemplate = new StringBuilder();
		int k = 0;
		while (k < template.length()) {
			int i1 = template.indexOf("${repeat:", k);
			if (i1 < 0) {
				newTemplate.append(template.substring(k));
				break;
			}

			int i2 = template.indexOf(':', i1 + 9);
			if (i2 < 0)
				throw new RuntimeException(
				        "Template error: Context variable name followed by : is required after repeat");

			// Find the closing }, store in i3
			int nn = 1;
			int i3 = -1;
			int i = i2;
			while (nn > 0 && i < template.length()) {
				i3 = template.indexOf('}', i);
				if (i3 < 0)
					throw new RuntimeException("Template error: Matching } not found");
				int i32 = template.indexOf('{', i);
				if (i32 >= 0 && i32 < i3) {
					nn++;
					i = i32 + 1;
				} else {
					nn--;
					i = i3 + 1;
				}
			}

			String var1 = template.substring(i1 + 9, i2);
			String value1 = ctx.getAttribute(var1);
			log.info("     " + var1 + ": " + value1);
			int n = 0;
			try {
				n = Integer.parseInt(value1);
			} catch (Exception e) {
				n = 0;
			}

			newTemplate.append(template.substring(k, i1));

			String rpt = template.substring(i2 + 1, i3);

			for (int ii = 0; ii < n; ii++) {
				String ss = rpt.replaceAll("\\[\\$\\{" + level + "\\}\\]", "[" + ii + "]");
				if (ii == n - 1 && ss.trim().endsWith(",")) {
					int i4 = ss.lastIndexOf(',');
					if (i4 > 0)
						ss = ss.substring(0, i4) + ss.substring(i4 + 1);
				}
				newTemplate.append(ss);
			}

			k = i3 + 1;
		}

		if (k == 0)
			return newTemplate.toString();

		return expandRepeats(ctx, newTemplate.toString(), level + 1);
	}

	private String readFile(String fileName) throws Exception {
		byte[] encoded = Files.readAllBytes(Paths.get(fileName));
		return new String(encoded, "UTF-8");
	}

	private HttpResponse sendHttpRequest(String request, Param p) throws Exception {
		ClientConfig config = new DefaultClientConfig();
		SSLContext ssl = null;
		if (p.ssl && p.restapiUrl.startsWith("https"))
			ssl = createSSLContext(p);
		if (ssl != null) {
			HostnameVerifier hostnameVerifier = new HostnameVerifier() {

				@Override
				public boolean verify(String hostname, SSLSession session) {
					return true;
				}
			};

			config.getProperties().put(HTTPSProperties.PROPERTY_HTTPS_PROPERTIES,
			        new HTTPSProperties(hostnameVerifier, ssl));
		}

		logProperties(config.getProperties());

		Client client = Client.create(config);
		client.setConnectTimeout(5000);
		client.addFilter(new HTTPBasicAuthFilter(p.restapiUser, p.restapiPassword));
		WebResource webResource = client.resource(p.restapiUrl);

		log.info("Sending request:");
		log.info(request);
		long t1 = System.currentTimeMillis();

		HttpResponse r = new HttpResponse();
		r.code = 200;

		if (!p.skipSending) {
			String tt = p.format == Format.XML ? "application/xml" : "application/json";
			String tt1 = tt + ";charset=UTF-8";

			ClientResponse response = null;
			if (p.httpMethod == HttpMethod.GET)
				response = webResource.accept(tt).type(tt1).get(ClientResponse.class);
			else if (p.httpMethod == HttpMethod.POST)
				response = webResource.accept(tt).type(tt1).post(ClientResponse.class, request);
			else if (p.httpMethod == HttpMethod.PUT)
				response = webResource.accept(tt).type(tt1).put(ClientResponse.class, request);
			else if (p.httpMethod == HttpMethod.DELETE)
				response = webResource.accept(tt).type(tt1).delete(ClientResponse.class, request);

			r.code = response.getStatus();
			r.headers = response.getHeaders();
			EntityTag etag = response.getEntityTag();
			if (etag != null)
				r.message = etag.getValue();
			if (response.hasEntity() && r.code != 204)
				r.body = response.getEntity(String.class);
		}

		long t2 = System.currentTimeMillis();
		log.info("Response received. Time: " + (t2 - t1));
		log.info("HTTP response code: " + r.code);
		log.info("HTTP response message: " + r.message);
		logHeaders(r.headers);
		log.info("HTTP response: " + r.body);

		return r;
	}

	private SSLContext createSSLContext(Param p) {
		try {
			System.setProperty("jsse.enableSNIExtension", "false");
			System.setProperty("javax.net.ssl.trustStore", p.trustStoreFileName);
			System.setProperty("javax.net.ssl.trustStorePassword", p.trustStorePassword);

			HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {

				@Override
				public boolean verify(String string, SSLSession ssls) {
					return true;
				}
			});

			KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			FileInputStream in = new FileInputStream(p.keyStoreFileName);
			KeyStore ks = KeyStore.getInstance("PKCS12");
			char[] pwd = p.keyStorePassword.toCharArray();
			ks.load(in, pwd);
			kmf.init(ks, pwd);

			SSLContext ctx = SSLContext.getInstance("TLS");
			ctx.init(kmf.getKeyManagers(), null, null);
			return ctx;
		} catch (Exception e) {
			log.error("Error creating SSLContext: " + e.getMessage(), e);
		}
		return null;
	}

	private static class HttpResponse {

		public int code;
		public String message;
		public String body;
		public MultivaluedMap<String, String> headers;
	}

	private void setResponseStatus(SvcLogicContext ctx, String prefix, HttpResponse r) {
		String pp = prefix != null ? prefix + '.' : "";
		ctx.setAttribute(pp + "response-code", String.valueOf(r.code));
		ctx.setAttribute(pp + "response-message", r.message);
	}

	public void sendFile(Map<String, String> paramMap, SvcLogicContext ctx) throws SvcLogicException {
		HttpResponse r = null;
		try {
			FileParam p = getFileParameters(paramMap);
			byte[] data = Files.readAllBytes(Paths.get(p.fileName));

			r = sendHttpData(data, p);
			setResponseStatus(ctx, p.responsePrefix, r);

		} catch (Exception e) {
			log.error("Error sending the request: " + e.getMessage(), e);

			r = new HttpResponse();
			r.code = 500;
			r.message = e.getMessage();
			String prefix = parseParam(paramMap, "responsePrefix", false, null);
			setResponseStatus(ctx, prefix, r);
		}

		if (r != null && r.code >= 300)
			throw new SvcLogicException(String.valueOf(r.code) + ": " + r.message);
	}

	private static class FileParam {

		public String fileName;
		public String url;
		public String user;
		public String password;
		public HttpMethod httpMethod;
		public String responsePrefix;
		public boolean skipSending;
	}

	private FileParam getFileParameters(Map<String, String> paramMap) throws SvcLogicException {
		FileParam p = new FileParam();
		p.fileName = parseParam(paramMap, "fileName", true, null);
		p.url = parseParam(paramMap, "url", true, null);
		p.user = parseParam(paramMap, "user", true, null);
		p.password = parseParam(paramMap, "password", true, null);
		p.httpMethod = HttpMethod.fromString(parseParam(paramMap, "httpMethod", false, "post"));
		p.responsePrefix = parseParam(paramMap, "responsePrefix", false, null);
		String skipSendingStr = paramMap.get("skipSending");
		p.skipSending = skipSendingStr != null && skipSendingStr.equalsIgnoreCase("true");
		return p;
	}

	private HttpResponse sendHttpData(byte[] data, FileParam p) {
		Client client = Client.create();
		client.setConnectTimeout(5000);
		client.setFollowRedirects(true);
		client.addFilter(new HTTPBasicAuthFilter(p.user, p.password));
		WebResource webResource = client.resource(p.url);

		log.info("Sending file");
		long t1 = System.currentTimeMillis();

		HttpResponse r = new HttpResponse();
		r.code = 200;

		if (!p.skipSending) {
			String tt = "application/octet-stream";

			ClientResponse response = null;
			if (p.httpMethod == HttpMethod.POST)
				response = webResource.accept(tt).type(tt).post(ClientResponse.class, data);
			else if (p.httpMethod == HttpMethod.PUT)
				response = webResource.accept(tt).type(tt).put(ClientResponse.class, data);

			r.code = response.getStatus();
			r.headers = response.getHeaders();
			EntityTag etag = response.getEntityTag();
			if (etag != null)
				r.message = etag.getValue();
			if (response.hasEntity() && r.code != 204)
				r.body = response.getEntity(String.class);

			if (r.code == 301) {
				String newUrl = response.getHeaders().getFirst("Location");

				log.info("Got response code 301. Sending same request to URL: " + newUrl);

				webResource = client.resource(newUrl);

				if (p.httpMethod == HttpMethod.POST)
					response = webResource.accept(tt).type(tt).post(ClientResponse.class, data);
				else if (p.httpMethod == HttpMethod.PUT)
					response = webResource.accept(tt).type(tt).put(ClientResponse.class, data);

				r.code = response.getStatus();
				etag = response.getEntityTag();
				if (etag != null)
					r.message = etag.getValue();
				if (response.hasEntity() && r.code != 204)
					r.body = response.getEntity(String.class);
			}
		}

		long t2 = System.currentTimeMillis();
		log.info("Response received. Time: " + (t2 - t1));
		log.info("HTTP response code: " + r.code);
		log.info("HTTP response message: " + r.message);
		logHeaders(r.headers);
		log.info("HTTP response: " + r.body);

		return r;
	}

	public void postMessageOnUeb(Map<String, String> paramMap, SvcLogicContext ctx) throws SvcLogicException {
		HttpResponse r = null;
		try {
			UebParam p = getUebParameters(paramMap);

			String pp = p.responsePrefix != null ? p.responsePrefix + '.' : "";

			String req = null;

			if (p.templateFileName == null) {
				log.info("No template file name specified. Using default UEB template: " + defaultUebTemplateFileName);
				p.templateFileName = defaultUebTemplateFileName;
			}

			String reqTemplate = readFile(p.templateFileName);
			reqTemplate = reqTemplate.replaceAll("rootVarName", p.rootVarName);
			req = buildXmlJsonRequest(ctx, reqTemplate, Format.JSON);

			r = postOnUeb(req, p);
			setResponseStatus(ctx, p.responsePrefix, r);
			if (r.body != null)
				ctx.setAttribute(pp + "httpResponse", r.body);

		} catch (Exception e) {
			log.error("Error sending the request: " + e.getMessage(), e);

			r = new HttpResponse();
			r.code = 500;
			r.message = e.getMessage();
			String prefix = parseParam(paramMap, "responsePrefix", false, null);
			setResponseStatus(ctx, prefix, r);
		}

		if (r != null && r.code >= 300)
			throw new SvcLogicException(String.valueOf(r.code) + ": " + r.message);
	}

	private static class UebParam {

		public String topic;
		public String templateFileName;
		public String rootVarName;
		public String responsePrefix;
		public boolean skipSending;
	}

	private UebParam getUebParameters(Map<String, String> paramMap) throws SvcLogicException {
		UebParam p = new UebParam();
		p.topic = parseParam(paramMap, "topic", true, null);
		p.templateFileName = parseParam(paramMap, "templateFileName", false, null);
		p.rootVarName = parseParam(paramMap, "rootVarName", false, null);
		p.responsePrefix = parseParam(paramMap, "responsePrefix", false, null);
		String skipSendingStr = paramMap.get("skipSending");
		p.skipSending = skipSendingStr != null && skipSendingStr.equalsIgnoreCase("true");
		return p;
	}

	private HttpResponse postOnUeb(String request, UebParam p) throws Exception {
		String[] urls = uebServers.split(" ");
		for (int i = 0; i < urls.length; i++) {
			if (!urls[i].endsWith("/"))
				urls[i] += "/";
			urls[i] += "events/" + p.topic;
		}

		Client client = Client.create();
		client.setConnectTimeout(5000);
		WebResource webResource = client.resource(urls[0]);

		log.info("UEB URL: " + urls[0]);
		log.info("Sending request:");
		log.info(request);
		long t1 = System.currentTimeMillis();

		HttpResponse r = new HttpResponse();
		r.code = 200;

		if (!p.skipSending) {
			String tt = "application/json";
			String tt1 = tt + ";charset=UTF-8";

			ClientResponse response = webResource.accept(tt).type(tt1).post(ClientResponse.class, request);

			r.code = response.getStatus();
			r.headers = response.getHeaders();
			if (response.hasEntity())
				r.body = response.getEntity(String.class);
		}

		long t2 = System.currentTimeMillis();
		log.info("Response received. Time: " + (t2 - t1));
		log.info("HTTP response code: " + r.code);
		logHeaders(r.headers);
		log.info("HTTP response:\n" + r.body);

		return r;
	}

	private void logProperties(Map<String, Object> mm) {
		List<String> ll = new ArrayList<>();
		for (Object o : mm.keySet())
			ll.add((String) o);
		Collections.sort(ll);

		log.info("Properties:");
		for (String name : ll)
			log.info("--- " + name + ": " + String.valueOf(mm.get(name)));
	}

	private void logHeaders(MultivaluedMap<String, String> mm) {
		log.info("HTTP response headers:");

		if (mm == null)
			return;

		List<String> ll = new ArrayList<>();
		for (Object o : mm.keySet())
			ll.add((String) o);
		Collections.sort(ll);

		for (String name : ll)
			log.info("--- " + name + ": " + String.valueOf(mm.get(name)));
	}

	public void setUebServers(String uebServers) {
		this.uebServers = uebServers;
	}

	public void setDefaultUebTemplateFileName(String defaultUebTemplateFileName) {
		this.defaultUebTemplateFileName = defaultUebTemplateFileName;
	}
}
