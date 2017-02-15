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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JsonParser {

	private static final Logger log = LoggerFactory.getLogger(JsonParser.class);

	@SuppressWarnings("unchecked")
	public static Map<String, String> convertToProperties(String s) throws JSONException {
		JSONObject json = new JSONObject(s);

		Map<String, Object> wm = new HashMap<String, Object>();
		Iterator<String> ii = json.keys();
		while (ii.hasNext()) {
			String key1 = ii.next();
			wm.put(key1, json.get(key1));
		}

		Map<String, String> mm = new HashMap<String, String>();

		while (!wm.isEmpty())
			for (String key : new ArrayList<>(wm.keySet())) {
				Object o = wm.get(key);
				wm.remove(key);

				if (o instanceof Boolean || o instanceof Number || o instanceof String) {
					mm.put(key, o.toString());

					log.info("Added property: " + key + ": " + o.toString());
				}

				else if (o instanceof JSONObject) {
					JSONObject jo = (JSONObject) o;
					Iterator<String> i = jo.keys();
					while (i.hasNext()) {
						String key1 = i.next();
						wm.put(key + "." + key1, jo.get(key1));
					}
				}

				else if (o instanceof JSONArray) {
					JSONArray ja = (JSONArray) o;
					mm.put(key + "_length", String.valueOf(ja.length()));

					log.info("Added property: " + key + "_length" + ": " + String.valueOf(ja.length()));

					for (int i = 0; i < ja.length(); i++)
						wm.put(key + '[' + i + ']', ja.get(i));
				}
			}

		return mm;
	}
}
