package org.openecomp.sdnc.restapicall;

public enum HttpMethod {
    GET, POST, PUT, DELETE, PATCH;

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
        if (s.equalsIgnoreCase("patch"))
            return PATCH;
        throw new IllegalArgumentException("Invalid value for HTTP Method: " + s);
    }
}
