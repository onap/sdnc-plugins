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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class XmlJsonUtil {

	private static final Logger log = LoggerFactory.getLogger(XmlJsonUtil.class);

	public static String getXml(Map<String, String> varmap, String var) {
		boolean escape = true;
		if (var.startsWith("'")) {
			var = var.substring(1);
			escape = false;
		}

		Object o = createStructure(varmap, var);
		return generateXml(o, 0, escape);
	}

	public static String getJson(Map<String, String> varmap, String var) {
		boolean escape = true;
		if (var.startsWith("'")) {
			var = var.substring(1);
			escape = false;
		}

		Object o = createStructure(varmap, var);
		return generateJson(o, escape);
	}

	private static Object createStructure(Map<String, String> flatmap, String var) {
		if (flatmap.containsKey(var)) {
			if (var.endsWith("_length") || var.endsWith("].key"))
				return null;
			return flatmap.get(var);
		}

		Map<String, Object> mm = new HashMap<>();
		for (String k : flatmap.keySet())
			if (k.startsWith(var + ".")) {
				int i1 = k.indexOf('.', var.length() + 1);
				int i2 = k.indexOf('[', var.length() + 1);
				int i3 = k.length();
				if (i1 > 0 && i1 < i3)
					i3 = i1;
				if (i2 > 0 && i2 < i3)
					i3 = i2;
				String k1 = k.substring(var.length() + 1, i3);
				String var1 = k.substring(0, i3);
				if (!mm.containsKey(k1)) {
					Object str = createStructure(flatmap, var1);
					if (str != null && (!(str instanceof String) || ((String) str).trim().length() > 0))
						mm.put(k1, str);
				}
			}
		if (!mm.isEmpty())
			return mm;

		boolean arrayFound = false;
		for (String k : flatmap.keySet())
			if (k.startsWith(var + "[")) {
				arrayFound = true;
				break;
			}

		if (arrayFound) {
			List<Object> ll = new ArrayList<>();

			int length = Integer.MAX_VALUE;
			String lengthStr = flatmap.get(var + "_length");
			if (lengthStr != null) {
				try {
					length = Integer.parseInt(lengthStr);
				} catch (Exception e) {
					log.warn("Invalid number for " + var + "_length:" + lengthStr);
				}
			}

			for (int i = 0; i < length; i++) {
				Object v = createStructure(flatmap, var + '[' + i + ']');
				if (v == null)
					break;
				ll.add(v);
			}

			if (!ll.isEmpty())
				return ll;
		}

		return null;
	}

	@SuppressWarnings("unchecked")
	private static String generateXml(Object o, int indent, boolean escape) {
		if (o == null)
			return null;

		if (o instanceof String)
			return escape ? escapeXml((String) o) : (String) o;;

		if (o instanceof Map) {
			StringBuilder ss = new StringBuilder();
			Map<String, Object> mm = (Map<String, Object>) o;
			for (String k : mm.keySet()) {
				Object v = mm.get(k);
				if (v instanceof String) {
					String s = escape ? escapeXml((String) v) : (String) v;
					ss.append(pad(indent)).append('<').append(k).append('>');
					ss.append(s);
					ss.append("</").append(k).append('>').append('\n');
				} else if (v instanceof Map) {
					ss.append(pad(indent)).append('<').append(k).append('>').append('\n');
					ss.append(generateXml(v, indent + 1, escape));
					ss.append(pad(indent)).append("</").append(k).append('>').append('\n');
				} else if (v instanceof List) {
					List<Object> ll = (List<Object>) v;
					for (Object o1 : ll) {
						ss.append(pad(indent)).append('<').append(k).append('>').append('\n');
						ss.append(generateXml(o1, indent + 1, escape));
						ss.append(pad(indent)).append("</").append(k).append('>').append('\n');
					}
				}
			}
			return ss.toString();
		}

		return null;
	}

	private static String generateJson(Object o, boolean escape) {
		if (o == null)
			return null;

		StringBuilder ss = new StringBuilder();
		generateJson(ss, o, 0, false, escape);
		return ss.toString();
	}

	@SuppressWarnings("unchecked")
	private static void generateJson(StringBuilder ss, Object o, int indent, boolean padFirst, boolean escape) {
		if (o instanceof String) {
			String s = escape ? escapeJson((String) o) : (String) o;
			if (padFirst)
				ss.append(pad(indent));
			ss.append('"').append(s).append('"');
			return;
		}

		if (o instanceof Map) {
			Map<String, Object> mm = (Map<String, Object>) o;

			if (padFirst)
				ss.append(pad(indent));
			ss.append("{\n");

			boolean first = true;
			for (String k : mm.keySet()) {
				if (!first)
					ss.append(",\n");
				first = false;

				Object v = mm.get(k);
				ss.append(pad(indent + 1)).append('"').append(k).append("\": ");
				generateJson(ss, v, indent + 1, false, escape);
			}

			ss.append("\n");
			ss.append(pad(indent)).append('}');

			return;
		}

		if (o instanceof List) {
			List<Object> ll = (List<Object>) o;

			if (padFirst)
				ss.append(pad(indent));
			ss.append("[\n");

			boolean first = true;
			for (Object o1 : ll) {
				if (!first)
					ss.append(",\n");
				first = false;

				generateJson(ss, o1, indent + 1, true, escape);
			}

			ss.append("\n");
			ss.append(pad(indent)).append(']');
		}
	}

	public static String removeLastCommaJson(String s) {
		StringBuilder sb = new StringBuilder();
		int k = 0;
		int start = 0;
		while (k < s.length()) {
			int i11 = s.indexOf('}', k);
			int i12 = s.indexOf(']', k);
			int i1 = -1;
			if (i11 < 0)
				i1 = i12;
			else if (i12 < 0)
				i1 = i11;
			else
				i1 = i11 < i12 ? i11 : i12;
			if (i1 < 0)
				break;

			int i2 = s.lastIndexOf(',', i1);
			if (i2 < 0) {
				k = i1 + 1;
				continue;
			}

			String between = s.substring(i2 + 1, i1);
			if (between.trim().length() > 0) {
				k = i1 + 1;
				continue;
			}

			sb.append(s.substring(start, i2));
			start = i2 + 1;
			k = i1 + 1;
		}

		sb.append(s.substring(start, s.length()));

		return sb.toString();
	}

	public static String removeEmptyStructJson(String s) {
		int k = 0;
		while (k < s.length()) {
			boolean curly = true;
			int i11 = s.indexOf('{', k);
			int i12 = s.indexOf('[', k);
			int i1 = -1;
			if (i11 < 0) {
				i1 = i12;
				curly = false;
			} else if (i12 < 0)
				i1 = i11;
			else
				if (i11 < i12)
					i1 = i11;
				else {
					i1 = i12;
					curly = false;
				}

			if (i1 >= 0) {
				int i2 = curly ? s.indexOf('}', i1) : s.indexOf(']', i1);
				if (i2 > 0) {
					String value = s.substring(i1 + 1, i2);
					if (value.trim().length() == 0) {
						int i4 = s.lastIndexOf('\n', i1);
						if (i4 < 0)
							i4 = 0;
						int i5 = s.indexOf('\n', i2);
						if (i5 < 0)
							i5 = s.length();

						s = s.substring(0, i4) + s.substring(i5);
						k = 0;
					} else
						k = i1 + 1;
				} else
					break;
			} else
				break;
		}

		return s;
	}

	public static String removeEmptyStructXml(String s) {
		int k = 0;
		while (k < s.length()) {
			int i1 = s.indexOf('<', k);
			if (i1 < 0 || i1 == s.length() - 1)
				break;

			char c1 = s.charAt(i1 + 1);
			if (c1 == '?' || c1 == '!') {
				k = i1 + 2;
				continue;
			}

			int i2 = s.indexOf('>', i1);
			if (i2 < 0) {
				k = i1 + 1;
				continue;
			}

			String closingTag = "</" + s.substring(i1 + 1, i2 + 1);
			int i3 = s.indexOf(closingTag, i2 + 1);
			if (i3 < 0) {
				k = i2 + 1;
				continue;
			}

			String value = s.substring(i2 + 1, i3);
			if (value.trim().length() > 0) {
				k = i2 + 1;
				continue;
			}

			int i4 = s.lastIndexOf('\n', i1);
			if (i4 < 0)
				i4 = 0;
			int i5 = s.indexOf('\n', i3);
			if (i5 < 0)
				i5 = s.length();

			s = s.substring(0, i4) + s.substring(i5);
			k = 0;
		}

		return s;
	}

	private static String escapeXml(String v) {
		String s = v.replaceAll("&", "&amp;");
		s = s.replaceAll("<", "&lt;");
		s = s.replaceAll("'", "&apos;");
		s = s.replaceAll("\"", "&quot;");
		s = s.replaceAll(">", "&gt;");
		return s;
	}

	private static String escapeJson(String v) {
		String s = v.replaceAll("\\\\", "\\\\\\\\");
		s = s.replaceAll("\"", "\\\\\"");
		return s;
	}

	private static String pad(int n) {
		String s = "";
		for (int i = 0; i < n; i++)
			s += '\t';
		return s;
	}
}
