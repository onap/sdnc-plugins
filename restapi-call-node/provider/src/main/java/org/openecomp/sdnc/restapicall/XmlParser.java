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

package org.openecomp.sdnc.restapicall;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

public class XmlParser {

	private static final Logger log = LoggerFactory.getLogger(XmlParser.class);

	public static Map<String, String> convertToProperties(String s, Set<String> listNameList) {
		Handler handler = new Handler(listNameList);
		try {
			SAXParserFactory factory = SAXParserFactory.newInstance();
			SAXParser saxParser = factory.newSAXParser();
			InputStream in = new ByteArrayInputStream(s.getBytes());
			saxParser.parse(in, handler);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return handler.getProperties();
	}

	private static class Handler extends DefaultHandler {

		private Set<String> listNameList;

		private Map<String, String> properties = new HashMap<>();

		public Map<String, String> getProperties() {
			return properties;
		}

		public Handler(Set<String> listNameList) {
			super();
			this.listNameList = listNameList;
			if (this.listNameList == null)
				this.listNameList = new HashSet<String>();
		}

		String currentName = "";
		String currentValue = "";

		@Override
		public void startElement(String uri, String localName, String qName, Attributes attributes)
		        throws SAXException {
			super.startElement(uri, localName, qName, attributes);

			String name = localName;
			if (name == null || name.trim().length() == 0)
				name = qName;
			int i2 = name.indexOf(':');
			if (i2 >= 0)
				name = name.substring(i2 + 1);

			if (currentName.length() > 0)
				currentName += '.';
			currentName += name;

			String listName = removeIndexes(currentName);

			if (listNameList.contains(listName)) {
				int len = getInt(properties, currentName + "_length");
				properties.put(currentName + "_length", String.valueOf(len + 1));
				currentName += "[" + len + "]";
			}
		}

		@Override
		public void endElement(String uri, String localName, String qName) throws SAXException {
			super.endElement(uri, localName, qName);

			String name = localName;
			if (name == null || name.trim().length() == 0)
				name = qName;
			int i2 = name.indexOf(':');
			if (i2 >= 0)
				name = name.substring(i2 + 1);

			if (currentValue.trim().length() > 0) {
				currentValue = currentValue.trim();
				properties.put(currentName, currentValue);

				log.info("Added property: " + currentName + ": " + currentValue);

				currentValue = "";
			}

			int i1 = currentName.lastIndexOf("." + name);
			if (i1 <= 0)
				currentName = "";
			else
				currentName = currentName.substring(0, i1);
		}

		@Override
		public void characters(char[] ch, int start, int length) throws SAXException {
			super.characters(ch, start, length);

			String value = new String(ch, start, length);
			currentValue += value;
		}

		private static int getInt(Map<String, String> mm, String name) {
			String s = mm.get(name);
			if (s == null)
				return 0;
			return Integer.parseInt(s);
		}

		private String removeIndexes(String currentName) {
			String s = "";
			boolean add = true;
			for (int i = 0; i < currentName.length(); i++) {
				char c = currentName.charAt(i);
				if (c == '[')
					add = false;
				else if (c == ']')
					add = true;
				else if (add)
					s += c;
			}
			return s;
		}
	}
}
