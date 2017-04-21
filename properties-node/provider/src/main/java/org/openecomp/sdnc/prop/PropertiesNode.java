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

package org.openecomp.sdnc.prop;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.Properties;

import org.openecomp.sdnc.sli.SvcLogicContext;
import org.openecomp.sdnc.sli.SvcLogicException;
import org.openecomp.sdnc.sli.SvcLogicJavaPlugin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PropertiesNode implements SvcLogicJavaPlugin {

	private static final Logger log = LoggerFactory.getLogger(PropertiesNode.class);

	public void readProperties(Map<String, String> paramMap, SvcLogicContext ctx) throws SvcLogicException {
		String fileName = parseParam(paramMap, "fileName", true, null);
		String contextPrefix = parseParam(paramMap, "contextPrefix", false, null);

		try {
			Properties pp = new Properties();
			InputStream in = new FileInputStream(fileName);
			pp.load(in);
			for (Object key : pp.keySet()) {
				String pfx = contextPrefix != null ? contextPrefix + '.' : "";
				String name = (String) key;
				String value = pp.getProperty(name);
				if (value != null && value.trim().length() > 0) {
					ctx.setAttribute(pfx + name, value.trim());
					log.info("+++ " + pfx + name + ": [" + value + "]");
				}
			}
		} catch (IOException e) {
			throw new SvcLogicException("Cannot read property file: " + fileName + ": " + e.getMessage(), e);
		}
	}

	private String parseParam(Map<String, String> paramMap, String name, boolean required, String def)
	        throws SvcLogicException {
		String s = paramMap.get(name);

		if (s == null || s.trim().length() == 0) {
			if (!required)
				return def;
			throw new SvcLogicException("Parameter " + name + " is required in PropertiesNode");
		}

		s = s.trim();
		String value = "";
		int i = 0;
		int i1 = s.indexOf('%');
		while (i1 >= 0) {
			int i2 = s.indexOf('%', i1 + 1);
			if (i2 < 0)
				throw new SvcLogicException("Cannot parse parameter " + name + ": " + s + ": no matching %");

			String varName = s.substring(i1 + 1, i2);
			String varValue = System.getenv(varName);
			if (varValue == null)
				varValue = "";

			value += s.substring(i, i1);
			value += varValue;

			i = i2 + 1;
			i1 = s.indexOf('%', i);
		}
		value += s.substring(i);

		log.info("Parameter " + name + ": " + value);
		return value;
	}
}
