/*
 * Copyright (C) 2015 Dell, Inc.
 *
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
 */

package com.quest.keycloak.protocol.wsfed.builders;

import com.quest.keycloak.common.wsfed.WSFedConstants;
import org.jboss.resteasy.specimpl.MultivaluedMapImpl;
import org.junit.Test;

import javax.ws.rs.core.MultivaluedMap;

import static org.junit.Assert.*;

/**
 * Created by dbarentine on 8/21/2015.
 */
public class WSFedProtocolParametersTest {
    @Test
    public void testFromParameters() {
        MultivaluedMap<String, String> requestParams = new MultivaluedMapImpl<>();
        requestParams.add(WSFedConstants.WSFED_ACTION, "action");
        requestParams.add(WSFedConstants.WSFED_REPLY, "reply");
        requestParams.add(WSFedConstants.WSFED_CONTEXT, "context");
        requestParams.add(WSFedConstants.WSFED_POLICY, "policy");
        requestParams.add(WSFedConstants.WSFED_CURRENT_TIME, "time");
        requestParams.add(WSFedConstants.WSFED_FEDERATION_ID, "fedid");
        requestParams.add(WSFedConstants.WSFED_ENCODING, "encoding");
        requestParams.add(WSFedConstants.WSFED_REALM, "realm");
        requestParams.add(WSFedConstants.WSFED_FRESHNESS, "freshness");
        requestParams.add(WSFedConstants.WSFED_AUTHENTICATION_LEVEL, "authlevel");
        requestParams.add(WSFedConstants.WSFED_TOKEN_REQUEST_TYPE, "trt");
        requestParams.add(WSFedConstants.WSFED_HOME_REALM, "homerealm");
        requestParams.add(WSFedConstants.WSFED_REQUEST_URL, "req");
        requestParams.add(WSFedConstants.WSFED_RESULT, "res");
        requestParams.add(WSFedConstants.WSFED_RESULT_URL, "resurl");

        WSFedProtocolParameters params = WSFedProtocolParameters.fromParameters(requestParams);
        assertEquals(requestParams.getFirst(WSFedConstants.WSFED_ACTION), params.getWsfedAction());
        assertEquals(requestParams.getFirst(WSFedConstants.WSFED_REPLY), params.getWsfedReply());
        assertEquals(requestParams.getFirst(WSFedConstants.WSFED_CONTEXT), params.getWsfedContext());
        assertEquals(requestParams.getFirst(WSFedConstants.WSFED_POLICY), params.getWsfedPolicy());
        assertEquals(requestParams.getFirst(WSFedConstants.WSFED_CURRENT_TIME), params.getWsfedCurrentTime());
        assertEquals(requestParams.getFirst(WSFedConstants.WSFED_FEDERATION_ID), params.getWsfedFederationId());
        assertEquals(requestParams.getFirst(WSFedConstants.WSFED_ENCODING), params.getWsfedEncoding());
        assertEquals(requestParams.getFirst(WSFedConstants.WSFED_REALM), params.getWsfedRealm());
        assertEquals(requestParams.getFirst(WSFedConstants.WSFED_FRESHNESS), params.getWsfedFreshness());
        assertEquals(requestParams.getFirst(WSFedConstants.WSFED_AUTHENTICATION_LEVEL), params.getWsfedAuthenticationLevel());
        assertEquals(requestParams.getFirst(WSFedConstants.WSFED_TOKEN_REQUEST_TYPE), params.getWsfedTokenRequestType());
        assertEquals(requestParams.getFirst(WSFedConstants.WSFED_HOME_REALM), params.getWsfedHomeRealm());
        assertEquals(requestParams.getFirst(WSFedConstants.WSFED_REQUEST_URL), params.getWsfedRequestUrl());
        assertEquals(requestParams.getFirst(WSFedConstants.WSFED_RESULT), params.getWsfedResult());
        assertEquals(requestParams.getFirst(WSFedConstants.WSFED_RESULT_URL), params.getWsfedResultUrl());
    }

    @Test
    public void testFromParametersNull() {
        MultivaluedMap<String, String> requestParams = new MultivaluedMapImpl<>();
        WSFedProtocolParameters params = WSFedProtocolParameters.fromParameters(requestParams);
        assertNull(params.getWsfedAction());
        assertNull(params.getWsfedReply());
        assertNull(params.getWsfedContext());
        assertNull(params.getWsfedPolicy());
        assertNull(params.getWsfedCurrentTime());
        assertNull(params.getWsfedFederationId());
        assertNull(params.getWsfedEncoding());
        assertNull(params.getWsfedRealm());
        assertNull(params.getWsfedFreshness());
        assertNull(params.getWsfedAuthenticationLevel());
        assertNull(params.getWsfedTokenRequestType());
        assertNull(params.getWsfedHomeRealm());
        assertNull(params.getWsfedRequestUrl());
        assertNull(params.getWsfedResult());
        assertNull(params.getWsfedResultUrl());
    }

    @Test
    public void testSetters() {
        WSFedProtocolParameters params = new WSFedProtocolParameters();

        params.setWsfedAction("action");
        params.setWsfedReply("reply");
        params.setWsfedContext("context");
        params.setWsfedPolicy("policy");
        params.setWsfedCurrentTime("time");
        params.setWsfedFederationId("fedid");
        params.setWsfedEncoding("encoding");
        params.setWsfedRealm("realm");
        params.setWsfedFreshness("freshness");
        params.setWsfedAuthenticationLevel("authlevel");
        params.setWsfedTokenRequestType("trt");
        params.setWsfedHomeRealm("homerealm");
        params.setWsfedRequestUrl("req");
        params.setWsfedResult("res");
        params.setWsfedResultUrl("resurl");

        assertEquals("action", params.getWsfedAction());
        assertEquals("reply", params.getWsfedReply());
        assertEquals("context", params.getWsfedContext());
        assertEquals("policy", params.getWsfedPolicy());
        assertEquals("time", params.getWsfedCurrentTime());
        assertEquals("fedid", params.getWsfedFederationId());
        assertEquals("encoding", params.getWsfedEncoding());
        assertEquals("realm", params.getWsfedRealm());
        assertEquals("freshness", params.getWsfedFreshness());
        assertEquals("authlevel", params.getWsfedAuthenticationLevel());
        assertEquals("trt", params.getWsfedTokenRequestType());
        assertEquals("homerealm", params.getWsfedHomeRealm());
        assertEquals("req", params.getWsfedRequestUrl());
        assertEquals("res", params.getWsfedResult());
        assertEquals("resurl", params.getWsfedResultUrl());
    }

}