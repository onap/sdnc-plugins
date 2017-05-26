package org.openecomp.sdnc.restapicall;

public enum Format {
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
