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

package com.quest.keycloak.common.wsfed.builders;

import com.quest.keycloak.common.wsfed.WSFedConstants;

import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.CacheControl;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import static org.keycloak.saml.common.util.StringUtil.isNotNull;

/**
 * This class builds the self-executing html form that is actually used as a response for a WS-FED passive requestor.
 * This corresponds to section 13.2.3 in the WS-Fed specification at
 * http://docs.oasis-open.org/wsfed/federation/v1.2/os/ws-federation-1.2-spec-os.html.
 * This class is also used for other types of responses, as the protocol specifies that all responses
 * follow the same method as for returning security tokens.
 */
public class WSFedResponseBuilder {
    protected String destination;
    protected String action;
    protected String realm;
    protected String context;
    protected String replyTo;
    protected String username;
    protected String method = HttpMethod.GET;

    public String getDestination() {
        return destination;
    }

    /**
     * Set's the destination - the response's HTML form's "action" value
     * TODO: check what this value actually is equal to... I'm going to guess client's "base url" for now
     * @param destination
     * @return this WSFedResponseBuilder
     */
    public WSFedResponseBuilder setDestination(String destination) {
        this.destination = destination;
        return this;
    }

    public String getAction() {
        return action;
    }

    /**
     * Sets the value to be used in the wrealm parameter.
     * @param action the action in the response must be the same as in the request.
     * @return this WSFedResponseBuilder
     */
    public WSFedResponseBuilder setAction(String action) {
        this.action = action;
        return this;
    }

    public String getRealm() {
        return realm;
    }

    /**
     * Sets the value to be used in the wrealm parameter.
     * @param realm the agreed on unique URI defined to identify the ws-fed realm (clientId in keycloak terms)
     * @return this WSFedResponseBuilder
     */
    public WSFedResponseBuilder setRealm(String realm) {
        this.realm = realm;
        return this;
    }

    public String getContext() {
        return context;
    }

    /**
     * Sets the value to be used in the wctx parameter.
     * @param context should represent the context from the original request
     * @return this WSFedResponseBuilder
     */
    public WSFedResponseBuilder setContext(String context) {
        this.context = context;
        return this;
    }

    public String getReplyTo() {
        return replyTo;
    }

    /**
     * Sets the value to be used in the wreply parameter.
     * @param replyTo the URL to reply to
     * @return this WSFedResponseBuilder
     */
    public WSFedResponseBuilder setReplyTo(String replyTo) {
        this.replyTo = replyTo;
        return this;
    }

    public String getMethod() {
        return method;
    }

    /**
     * Sets the value to be used for the form method in the HTTP response
     * @param method GET or POST
     * @return this WSFedResponseBuilder
     */
    public WSFedResponseBuilder setMethod(String method) {
        this.method = method;
        return this;
    }

    public String getUsername() {
        return username;
    }

    /**
     * Sets the username
     * FIXME this is pretty pointless as it is not used in the response
     * @param username
     * @return this WSFedResponseBuilder
     */
    public WSFedResponseBuilder setUsername(String username) {
        this.username = username;
        return this;
    }

    /**
     * Builds the javax Response containing the actual OK response with the self-executing control.
     * FIXME I'm pretty sure that the CacheControl is pretty useless here since it isn't used in any ResponseBuilder.
     * @param result the value to be set in the wresult field. Must be a <wst:RequestSecurityTokenResponse> element
     *               or a <wst:RequestSecurityTokenResponseCollection> element. This is basically the important part of
     *               the response.
     * @return The 200 OK response containing the self-executing form.
     */
    public Response buildResponse(String result) {
        String str = buildHtml(destination, action, result, realm, context, username);

        CacheControl cacheControl = new CacheControl();
        cacheControl.setNoCache(true);
        return Response.ok(str, MediaType.TEXT_HTML_TYPE)
                .header("Pragma", "no-cache")
                .header("Cache-Control", "no-cache, no-store").build();
    }

    /**
     * Creates the actual HTML response form as a String value.
     * FIXME There's no current actual reason to have this method seperated from the buildResponse, and even less to have all values in the method call. Either create a unit test that justifies this structure, or merge with buildResponse method
     *
     * @param destination the response's HTML form's "action" value
     * @param action the wa value
     * @param result the wresult value
     * @param realm the wrealm value (the client ID for keycloak)
     * @param context the wctx value
     * @param username - username, but unused
     * @return a string containing the full HTML response form for the response
     */
    protected String buildHtml(String destination, String action, String result, String realm, String context, String username) {
        StringBuilder builder = new StringBuilder();

        builder.append("<HTML>")
            .append("<HEAD>")
            .append("<TITLE>HTTP Binding Response (Response)</TITLE>")
            .append("</HEAD>")
            .append("<BODY Onload=\"document.forms[0].submit()\">")
            .append("<FORM METHOD=\"").append(method).append("\" ACTION=\"").append(destination).append("\">");

        String[][] params = new String[][] {
            { WSFedConstants.WSFED_ACTION, action },
            //FIXME check if this is necessary (i.e. actually used), as wrealm doesn't seem to be part of the protocol for responses.
            { WSFedConstants.WSFED_REALM, realm },
            { WSFedConstants.WSFED_RESULT, result!=null ? escapeAttribute(result) : null },
            //FIXME check if this is necessary (i.e. actually used), as wreply doesn't seem to be part of the protocol for responses.
            { WSFedConstants.WSFED_REPLY, replyTo },
            { WSFedConstants.WSFED_CONTEXT, context }
        };
        for(String[] p : params) {
            if (isNotNull(p[1])) {
                builder.append("<INPUT TYPE=\"HIDDEN\" NAME=\"").append(p[0]).append("\" VALUE=\"").append(p[1]).append("\" />");
            }
        }

        return builder.append("<NOSCRIPT>")
            .append("<P>JavaScript is disabled. We strongly recommend to enable it. Click the button below to continue.</P>")
            .append("<INPUT TYPE=\"SUBMIT\" VALUE=\"CONTINUE\" />")
            .append("</NOSCRIPT>")
            .append("</FORM></BODY></HTML>")
            .toString();
    }

    /**
     * Goes through every value of the string in parameter to replace "illegal" characters by their escaped value.
     * @param s The string to "escape"
     * @return the inpt string with "illegal" characters transformed for correctness
     */
    protected static String escapeAttribute(String s) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c > 127 || c == '"' || c == '<' || c == '>') {
                out.append("&#" + (int) c + ";");
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }
}
