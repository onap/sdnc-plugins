/*-
 * ============LICENSE_START=======================================================
 * openECOMP : SDN-C
 * ================================================================================
 * Copyright (C) 2017 AT&T Intellectual Property. All rights
 * 						reserved.
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

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.Test;
import org.openecomp.sdnc.restapicall.XmlParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TestXmlParser {

	private static final Logger log = LoggerFactory.getLogger(TestXmlParser.class);

	@Test
	public void test() throws Exception {
		BufferedReader in = new BufferedReader(new InputStreamReader(ClassLoader.getSystemResourceAsStream("test3.xml")));
		String ss = "";
		String line = null;
		while ((line = in.readLine()) != null)
			ss += line + '\n';

		Set<String> listNameList = new HashSet<String>();
		listNameList.add("project.dependencies.dependency");
		listNameList.add("project.build.plugins.plugin");
		listNameList.add("project.build.plugins.plugin.executions.execution");
		listNameList.add("project.build.pluginManagement.plugins.plugin");
		listNameList.add(
		        "project.build.pluginManagement.plugins.plugin.configuration.lifecycleMappingMetadata.pluginExecutions.pluginExecution");

		Map<String, String> mm = XmlParser.convertToProperties(ss, listNameList);

		logProperties(mm);

		in.close();
	}

	private void logProperties(Map<String, String> mm) {
		List<String> ll = new ArrayList<>();
		for (Object o : mm.keySet())
			ll.add((String) o);
		Collections.sort(ll);

		log.info("Properties:");
		for (String name : ll)
			log.info("--- " + name + ": " + mm.get(name));
	}
}
