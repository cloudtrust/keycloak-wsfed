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

import java.util.function.Consumer;

import javax.ws.rs.core.MultivaluedMap;

/**
 * WS-Fed parameter class.
 * From http://docs.oasis-open.org/wsfed/federation/v1.2/os/ws-federation-1.2-spec-os.html
 *
 * This class holds the state of all WS-Fed parameters from chapter 13.2 HTTP Protocol syntax, but currently only
 * 13.2.1 Parameters
 * 13.2.2 Requesting Security Tokens
 * 13.2.3 Returning Security Tokens
 * 13.2.4 Sign-Out Request Syntax
 *
 * are implemented
 */
public class WSFedProtocolParameters {
    protected String wsfedAction;
    protected String wsfedReply;
    protected String wsfedResource;
    protected String wsfedContext;
    protected String wsfedPolicy;
    protected String wsfedCurrentTime;
    protected String wsfedFederationId;
    protected String wsfedEncoding;
    protected String wsfedRealm;
    protected String wsfedFreshness;
    protected String wsfedAuthenticationLevel;
    protected String wsfedTokenRequestType;
    protected String wsfedHomeRealm;
    protected String wsfedRequestUrl;
    protected String wsfedResult;
    protected String wsfedResultUrl;

    /**
     * Sets the WS-Fed parameters from a Multivalued map. Such a map is typically returned by an http request form
     * parameters (POST) or an uri's parameters (GET). This method takes the first instance of a parameter, which is
     * fair, as the WS-Fed protocol doesn't specify what to do if a same parameter is set multiple times.
     *
     * @param requestParams a multivalued map. Expected to contain a browser's input ws-fed parameters.
     * @return a new WSFedProtocolParameters with all existing parameters filled in.
     */
    public static WSFedProtocolParameters fromParameters(MultivaluedMap<String, String> requestParams) {
        WSFedProtocolParameters params = new WSFedProtocolParameters();

        whenContainsKey(requestParams, WSFedConstants.WSFED_ACTION, params::setWsfedAction);
        whenContainsKey(requestParams, WSFedConstants.WSFED_REPLY, params::setWsfedReply);
        whenContainsKey(requestParams, WSFedConstants.WSFED_RESOURCE, params::setWsfedResource);
        whenContainsKey(requestParams, WSFedConstants.WSFED_CONTEXT, params::setWsfedContext);
        whenContainsKey(requestParams, WSFedConstants.WSFED_POLICY, params::setWsfedPolicy);
        whenContainsKey(requestParams, WSFedConstants.WSFED_CURRENT_TIME, params::setWsfedCurrentTime);
        whenContainsKey(requestParams, WSFedConstants.WSFED_FEDERATION_ID, params::setWsfedFederationId);
        whenContainsKey(requestParams, WSFedConstants.WSFED_ENCODING, params::setWsfedEncoding);
        whenContainsKey(requestParams, WSFedConstants.WSFED_REALM, params::setWsfedRealm);
        whenContainsKey(requestParams, WSFedConstants.WSFED_FRESHNESS, params::setWsfedFreshness);
        whenContainsKey(requestParams, WSFedConstants.WSFED_AUTHENTICATION_LEVEL, params::setWsfedAuthenticationLevel);
        whenContainsKey(requestParams, WSFedConstants.WSFED_TOKEN_REQUEST_TYPE, params::setWsfedTokenRequestType);
        whenContainsKey(requestParams, WSFedConstants.WSFED_HOME_REALM, params::setWsfedHomeRealm);
        whenContainsKey(requestParams, WSFedConstants.WSFED_REQUEST_URL, params::setWsfedRequestUrl);
        whenContainsKey(requestParams, WSFedConstants.WSFED_RESULT, params::setWsfedResult);
        whenContainsKey(requestParams, WSFedConstants.WSFED_RESULT_URL, params::setWsfedResultUrl);

        return params;
    }

    private static void whenContainsKey(MultivaluedMap<String, String> params, String key, Consumer<String> setter) {
        if (params.containsKey(key)) {
            setter.accept(params.getFirst(key));
        }
    }

    public String getWsfedAction() {
        return wsfedAction;
    }

    public void setWsfedAction(String wsfedAction) {
        this.wsfedAction = wsfedAction;
    }

    public String getWsfedReply() {
        return wsfedReply;
    }

    public void setWsfedReply(String wsfedReply) {
        this.wsfedReply = wsfedReply;
    }

    public String getWsfedResource() {
        return  wsfedResource;
    }

    public void setWsfedResource(String wsfedResource) {
        this.wsfedResource = wsfedResource;
    }

    public String getWsfedContext() {
        return wsfedContext;
    }

    public void setWsfedContext(String wsfedContext) {
        this.wsfedContext = wsfedContext;
    }

    public String getWsfedPolicy() {
        return wsfedPolicy;
    }

    public void setWsfedPolicy(String wsfedPolicy) {
        this.wsfedPolicy = wsfedPolicy;
    }

    public String getWsfedCurrentTime() {
        return wsfedCurrentTime;
    }

    public void setWsfedCurrentTime(String wsfedCurrentTime) {
        this.wsfedCurrentTime = wsfedCurrentTime;
    }

    public String getWsfedFederationId() {
        return wsfedFederationId;
    }

    public void setWsfedFederationId(String wsfedFederationId) {
        this.wsfedFederationId = wsfedFederationId;
    }

    public String getWsfedEncoding() {
        return wsfedEncoding;
    }

    public void setWsfedEncoding(String wsfedEncoding) {
        this.wsfedEncoding = wsfedEncoding;
    }

    public String getWsfedRealm() {
        return wsfedRealm;
    }

    public void setWsfedRealm(String wsfedRealm) {
        this.wsfedRealm = wsfedRealm;
    }

    public String getWsfedFreshness() {
        return wsfedFreshness;
    }

    public void setWsfedFreshness(String wsfedFreshness) {
        this.wsfedFreshness = wsfedFreshness;
    }

    public String getWsfedAuthenticationLevel() {
        return wsfedAuthenticationLevel;
    }

    public void setWsfedAuthenticationLevel(String wsfedAuthenticationLevel) {
        this.wsfedAuthenticationLevel = wsfedAuthenticationLevel;
    }

    public String getWsfedTokenRequestType() {
        return wsfedTokenRequestType;
    }

    public void setWsfedTokenRequestType(String wsfedTokenRequestType) {
        this.wsfedTokenRequestType = wsfedTokenRequestType;
    }

    public String getWsfedHomeRealm() {
        return wsfedHomeRealm;
    }

    public void setWsfedHomeRealm(String wsfedHomeRealm) {
        this.wsfedHomeRealm = wsfedHomeRealm;
    }

    public String getWsfedRequestUrl() {
        return wsfedRequestUrl;
    }

    public void setWsfedRequestUrl(String wsfedRequestUrl) {
        this.wsfedRequestUrl = wsfedRequestUrl;
    }

    public String getWsfedResult() {
        return wsfedResult;
    }

    public void setWsfedResult(String wsfedResult) {
        this.wsfedResult = wsfedResult;
    }

    public String getWsfedResultUrl() {
        return wsfedResultUrl;
    }

    public void setWsfedResultUrl(String wsfedResultUrl) {
        this.wsfedResultUrl = wsfedResultUrl;
    }
}
