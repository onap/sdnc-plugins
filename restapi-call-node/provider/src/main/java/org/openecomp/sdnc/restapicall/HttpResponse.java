package org.openecomp.sdnc.restapicall;

import javax.ws.rs.core.MultivaluedMap;

public class HttpResponse {
    public int code;
    public String message;
    public String body;
    public MultivaluedMap<String, String> headers;
}
