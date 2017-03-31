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

import java.util.HashMap;
import java.util.Map;

import org.junit.Assert;
import org.junit.Test;
import org.openecomp.sdnc.restapicall.XmlJsonUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class TestXmlJsonUtil {

    private static final Logger log = LoggerFactory.getLogger(TestXmlJsonUtil.class);

    @Test
    public void test() {
        Map<String, String> mm = new HashMap<>();
        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].vnf-type", "N-SBG");
        mm.put("service-data.service-information.service-instance-id", "someinstance001");
        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].dns-server-ip-address", "10.11.12.13");
        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].escf-domain-name", "hclab.atttest.com");
        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].snmp-target-v3_length", "2");
        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].snmp-target-v3[0].snmp-target-v3-id", "1");
        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].snmp-target-v3[0].snmp-target-ip-address", "127.0.0.1");
        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].snmp-target-v3[0].snmp-security-level", "NO_AUTH_NO_PRIV");
        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].snmp-target-v3[1].snmp-target-v3-id", "2");
        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].snmp-target-v3[1].snmp-target-ip-address", "192.168.1.8");
        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].snmp-target-v3[1].snmp-security-level", "NO_AUTH_NO_PRIV");
        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].dns-ip-address-1", "2001:1890:1001:2224::1");
        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].dns-ip-address-2", "2001:1890:1001:2424::1");
        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].diameter-rf-realm-name", "uvp.els-an.att.net");
        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].diameter-rf-peer-ip-address", "192.168.1.66");
        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].bgf-controller-ip-address", "192.168.1.186");
        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].bgf-control-link-name", "mg3/69@192.168.1.226");
        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].rf-interface-nexthop-ip-address", "10.111.108.150");
        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].rf-mated-pair-ip-address", "10.111.108.146");

        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].access-net-pcscf_length", "4");

        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].access-net-pcscf[0].network-name", "UvpbUgnAccess1");
        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].access-net-pcscf[0].sip-pa-termination-ip-address", "10.111.108.146");

        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].access-net-pcscf[1].network-name", "MIS");
        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].access-net-pcscf[1].proactive-transcoding-profile", "trinity-transcodingProfile");
        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].access-net-pcscf[1].next-hop-ip-address", "10.111.108.158");
        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].access-net-pcscf[1].subnet-mask-length", "10.111.108.154");

        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].access-net-pcscf[2].network-name", "AVPN1");
        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].access-net-pcscf[2].proactive-transcoding-profile", "trinity-transcodingProfile");
        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].access-net-pcscf[2].next-hop-ip-address", "10.111.108.166");
        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].access-net-pcscf[2].subnet-mask-length", "10.111.108.162");

        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].access-net-pcscf[3].network-name", "AVPN1");
        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].access-net-pcscf[3].proactive-transcoding-profile", "trinity-transcodingProfile");
        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].access-net-pcscf[3].next-hop-ip-address", "10.129.108.166");
        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].access-net-pcscf[3].subnet-mask-length", "10.129.108.162");

        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].core-net-pcscf_length", "1");

        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].core-net-pcscf[0].network-name", "Core");
        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].core-net-pcscf[0].next-hop-ip-address", "10.111.108.142");
        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].core-net-pcscf[0].sip-pa-termination-ip-address", "10.111.108.138");

        mm.put("service-data.vnf-config-parameters-list.vnf-config-parameters[0].mated-pair-fully-qualified-domain-name", "mt1nj01sbg01pyl-mt1nj01sbg02pyl.ar1ga.uvp.els-an.att.net");

        mm.put("service-data.appc-request-header.svc-request-id", "SOMESERVICEREQUEST123451000");
        mm.put("service-data.vnf-config-information.vnf-host-ip-address", "192.168.13.151");
        mm.put("service-data.vnf-config-information.vendor", "Netconf");

        mm.put("service-data.vnf-config-information.escape-test", "blah blah \"xxx&nnn<>\\'\"there>blah<&''\"\"123\\\\\\'''blah blah &");

        String ss = XmlJsonUtil.getXml(mm, "service-data.vnf-config-parameters-list");
        log.info(ss);

        ss = XmlJsonUtil.getXml(mm, "service-data.vnf-config-information");
        log.info(ss);

        ss = XmlJsonUtil.getJson(mm, "service-data.vnf-config-parameters-list.vnf-config-parameters");
        log.info(ss);

        ss = XmlJsonUtil.getJson(mm, "service-data.vnf-config-information");
        log.info(ss);
    }

    @Test
    public void testRemoveEmptyStructXml() {
        String xmlin = "" +
                "<T1>\n" +
                "    <T2>\n" +
                "        <T3>\n" +
                "            <T4></T4>\n" +
                "            <T5>     </T5>\n" +
                "            <T6>\n" +
                "            </T6>\n" +
                "        </T3>\n" +
                "        <T7>blah</T7>\n" +
                "    </T2>\n" +
                "    <T8>\n" +
                "        <T9>\n" +
                "            <T10></T10>\n" +
                "            <T11>      </T11>\n" +
                "            <T12>\n" +
                "            </T12>\n" +
                "        </T9>\n" +
                "        <T13>\n" +
                "            <T14></T14>\n" +
                "            <T15>     </T15>\n" +
                "            <T16>\n" +
                "                <T17></T17>\n" +
                "            </T16>\n" +
                "        </T13>\n" +
                "        <T17>\n" +
                "        </T17>\n" +
                "    </T8>\n" +
                "    <T18>blah blah</T18>\n" +
                "</T1>\n";

        String xmloutexpected = "" +
                "<T1>\n" +
                "    <T2>\n" +
                "        <T7>blah</T7>\n" +
                "    </T2>\n" +
                "    <T18>blah blah</T18>\n" +
                "</T1>\n";

        String xmlout = XmlJsonUtil.removeEmptyStructXml(xmlin);
        log.info(xmlout);

        Assert.assertEquals(xmloutexpected, xmlout);
    }

    @Test
    public void testRemoveEmptyStructJson() {
        String xmlin = "{\r\n" +
                "    \"T1\":{\r\n" +
                "        \"T2\":{\r\n" +
                "            \"T3\":[\r\n" +
                "                                \r\n" +
                "            ],\r\n" +
                "            \"T4\":{\r\n" +
                "                \"T12\":[\r\n" +
                "                    \r\n" +
                "                ],\r\n" +
                "                \"T13\":[   ],\r\n" +
                "                \"T14\":{\r\n" +
                "                    \"T15\":{\r\n" +
                "                        \r\n" +
                "                    },\r\n" +
                "                    \"T16\":{\r\n" +
                "                        \r\n" +
                "                    }\r\n" +
                "                }\r\n" +
                "            },\r\n" +
                "            \"T5\":{\r\n" +
                "                \"T6\":[\r\n" +
                "                    \r\n" +
                "                ],\r\n" +
                "                \"T7\":[\r\n" +
                "                    \"T8\":{\r\n" +
                "                        \r\n" +
                "                    },\r\n" +
                "                    \"T9\":{    },\r\n" +
                "                    \"T10\":\"blah\",\r\n" +
                "                    \"T11\":[\r\n" +
                "                        \r\n" +
                "                    ]\r\n" +
                "                ]\r\n" +
                "            }\r\n" +
                "        }\r\n" +
                "    }\r\n" +
                "}\r\n" +
                "";

        String xmloutexpected = "{\r\n" +
                "    \"T1\":{\r\n" +
                "        \"T2\":{\r\n" +
                "            \"T5\":{\r\n" +
                "                \"T7\":[\r\n" +
                "                    \"T10\":\"blah\",\r\n" +
                "                ]\r\n" +
                "            }\r\n" +
                "        }\r\n" +
                "    }\r\n" +
                "}\r\n" +
                "";

        String xmlout = XmlJsonUtil.removeEmptyStructJson(xmlin);
        log.info(xmlout);

        Assert.assertEquals(xmloutexpected, xmlout);
    }
}
