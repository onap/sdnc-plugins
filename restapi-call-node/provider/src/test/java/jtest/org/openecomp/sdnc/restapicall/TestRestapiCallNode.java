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

package jtest.org.openecomp.sdnc.restapicall;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;
import org.openecomp.sdnc.restapicall.RestapiCallNode;
import org.openecomp.sdnc.sli.SvcLogicContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TestRestapiCallNode {

	private static final Logger log = LoggerFactory.getLogger(TestRestapiCallNode.class);


	@Test
	public void testDelete() throws Exception {
		SvcLogicContext ctx = new SvcLogicContext();

		Map<String, String> p = new HashMap<String, String>();
		p.put("restapiUrl", "https://echo.getpostman.com/delete");
		p.put("restapiUser", "user1");
		p.put("restapiPassword", "pwd1");
		p.put("httpMethod", "delete");
		p.put("skipSending", "true");

		RestapiCallNode rcn = new RestapiCallNode();
		rcn.sendRequest(p, ctx);
	}

	@Test
	public void testJsonTemplate() throws Exception {
		SvcLogicContext ctx = new SvcLogicContext();
		ctx.setAttribute("tmp.sdn-circuit-req-row_length", "3");
		ctx.setAttribute("tmp.sdn-circuit-req-row[0].source-uid", "APIDOC-123");
		ctx.setAttribute("tmp.sdn-circuit-req-row[0].action", "delete");
		ctx.setAttribute("tmp.sdn-circuit-req-row[0].request-timestamp", "2016-09-09 16:30:35.0");
		ctx.setAttribute("tmp.sdn-circuit-req-row[0].request-status", "New");
		ctx.setAttribute("tmp.sdn-circuit-req-row[0].processing-status", "New");
		ctx.setAttribute("tmp.sdn-circuit-req-row[0].service-clfi", "testClfi1");
		ctx.setAttribute("tmp.sdn-circuit-req-row[0].clci", "clci");
		ctx.setAttribute("tmp.sdn-circuit-req-row[1].source-uid", "APIDOC-123");
		ctx.setAttribute("tmp.sdn-circuit-req-row[1].action", "delete");
		ctx.setAttribute("tmp.sdn-circuit-req-row[1].request-timestamp", "2016-09-09 16:30:35.0");
		ctx.setAttribute("tmp.sdn-circuit-req-row[1].request-status", "New");
		ctx.setAttribute("tmp.sdn-circuit-req-row[1].processing-status", "New");
		ctx.setAttribute("tmp.sdn-circuit-req-row[1].service-clfi", "testClfi1");
		ctx.setAttribute("tmp.sdn-circuit-req-row[1].clci", "clci");
		ctx.setAttribute("tmp.sdn-circuit-req-row[2].source-uid", "APIDOC-123");
		ctx.setAttribute("tmp.sdn-circuit-req-row[2].action", "delete");
		ctx.setAttribute("tmp.sdn-circuit-req-row[2].request-timestamp", "2016-09-09 16:30:35.0");
		ctx.setAttribute("tmp.sdn-circuit-req-row[2].request-status", "New");
		ctx.setAttribute("tmp.sdn-circuit-req-row[2].processing-status", "New");
		ctx.setAttribute("tmp.sdn-circuit-req-row[2].service-clfi", "testClfi1");
		ctx.setAttribute("tmp.sdn-circuit-req-row[2].clci", "clci");

		Map<String, String> p = new HashMap<String, String>();
		p.put("templateFileName", "src/test/resources/test-template.json");
		p.put("restapiUrl", "http://echo.getpostman.com");
		p.put("restapiUser", "user1");
		p.put("restapiPassword", "abc123");
		p.put("format", "json");
		p.put("httpMethod", "post");
		p.put("responsePrefix", "response");
		p.put("skipSending", "true");

		RestapiCallNode rcn = new RestapiCallNode();
		rcn.sendRequest(p, ctx);
	}
}
