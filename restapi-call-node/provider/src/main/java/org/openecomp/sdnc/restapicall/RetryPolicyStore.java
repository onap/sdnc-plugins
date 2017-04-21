/*-
 * ============LICENSE_START=======================================================
 * openECOMP : SDN-C
 * ================================================================================
 * Copyright (C) 2017 AT&T Intellectual Property. All rights
 * 							reserved.
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

import java.util.HashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RetryPolicyStore {
    private static final Logger log = LoggerFactory.getLogger(RetryPolicyStore.class);

    HashMap<String, RetryPolicy> retryPolicies;
    public String proxyServers;

    public String getProxyServers() {
        return proxyServers;
    }

    public void setProxyServers(String admServers) {
        this.proxyServers = admServers;
        String[] adminServersArray = admServers.split(",");
        RetryPolicy adminPortalRetry = new RetryPolicy(adminServersArray, adminServersArray.length);
        retryPolicies.put("dme2proxy", adminPortalRetry);
    }

    public RetryPolicyStore() {
        retryPolicies = new HashMap<String, RetryPolicy>();
    }
    
    public RetryPolicy getRetryPolicy(String policyName) {
        return (this.retryPolicies.get(policyName));
    }

}
