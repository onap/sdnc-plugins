package org.openecomp.sdnc.restapicall;

import java.util.Set;

public class Parameters {
    public String templateFileName;
    public String restapiUrl;
    public String restapiUser;
    public String restapiPassword;
    public Format format;
    public String contentType;
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
    public String customHttpHeaders;
    public String partner;
    public Boolean dumpHeaders;
}
