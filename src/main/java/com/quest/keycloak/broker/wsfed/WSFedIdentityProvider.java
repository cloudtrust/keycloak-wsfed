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

package com.quest.keycloak.broker.wsfed;

import com.quest.keycloak.common.wsfed.WSFedConstants;
import com.quest.keycloak.common.wsfed.builders.WSFedResponseBuilder;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.IdentityProviderDataMarshaller;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.common.util.PemUtils;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.*;
import org.keycloak.services.resources.RealmsResource;

import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URLEncoder;
import java.util.stream.Collectors;

public class WSFedIdentityProvider extends AbstractIdentityProvider<WSFedIdentityProviderConfig> {
    protected static final Logger logger = Logger.getLogger(WSFedIdentityProvider.class);

    public WSFedIdentityProvider(KeycloakSession session, WSFedIdentityProviderConfig config) {
        super(session, config);
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new WSFedEndpoint(realm, this, getConfig(), callback);
    }

    @Override
    public Response performLogin(AuthenticationRequest request) {
        try {
            String destinationUrl = getConfig().getSingleSignOnServiceUrl();
            String reply = request.getRedirectUri();
            String wsFedRealm = getConfig().getWsFedRealm();
            String context = request.getState().getEncoded();
            // not sure how valuable this null-check is in real life, but it breaks in the tests without it.
            if (request.getHttpRequest() != null && request.getHttpRequest().getUri() != null) {
                MultivaluedMap<String, String> params = request.getHttpRequest().getUri().getQueryParameters();
                if (params != null && params.containsKey("login_hint")) {
                    String loginHint = params.getFirst("login_hint");
                    context += "&username=" + URLEncoder.encode(loginHint, "UTF-8");
                }
            }
            WSFedResponseBuilder builder = new WSFedResponseBuilder()
                    .setAction(WSFedConstants.WSFED_SIGNIN_ACTION)
                    .setRealm(wsFedRealm)
                    .setReplyTo(reply)
                    .setDestination(destinationUrl)
                    .setContext(context);

            return builder.buildResponse(null);
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not create authentication request.", e);
        }
    }

    @Override
    public Response retrieveToken(KeycloakSession session, FederatedIdentityModel identity) {
        return Response.ok(identity.getToken()).build();
    }

    @Override
    public Response keycloakInitiatedBrowserLogout(KeycloakSession session, UserSessionModel userSession, UriInfo uriInfo, RealmModel realm) {
        String singleLogoutServiceUrl = getConfig().getSingleLogoutServiceUrl();
        if (singleLogoutServiceUrl == null || singleLogoutServiceUrl.trim().isEmpty()) {
            return null;
        }

        if (getConfig().isBackchannelSupported()) {
            backchannelLogout(session, userSession, uriInfo, realm);
            return null;
        }

        //Generate signout to IDP
        WSFedResponseBuilder builder = new WSFedResponseBuilder();
        builder.setMethod(HttpMethod.GET)
                .setAction(WSFedConstants.WSFED_SIGNOUT_ACTION)
                .setRealm(getConfig().getWsFedRealm())
                .setContext(userSession.getId())
                .setReplyTo(getEndpoint(uriInfo, realm))
                .setDestination(singleLogoutServiceUrl);

        return builder.buildResponse(null);
    }

    @Override
    public void backchannelLogout(KeycloakSession session, UserSessionModel userSession, UriInfo uriInfo, RealmModel realm) {
        String singleLogoutServiceUrl = getConfig().getSingleLogoutServiceUrl();
        if (singleLogoutServiceUrl == null || singleLogoutServiceUrl.trim().equals("") || !getConfig().isBackchannelSupported())
            return;

        try {
            int status = SimpleHttp.doGet(singleLogoutServiceUrl, session)
                    .param(WSFedConstants.WSFED_ACTION, WSFedConstants.WSFED_SIGNOUT_ACTION)
                    .param(WSFedConstants.WSFED_REALM, getConfig().getWsFedRealm()).asStatus();

            boolean success = status >= 200 && status < 400;
            if (!success) {
                logger.warn("Failed ws-fed backchannel broker logout to: " + singleLogoutServiceUrl);
            }
        } catch (Exception e) {
            logger.warn("Failed ws-fed backchannel broker logout to: " + singleLogoutServiceUrl, e);
        }
    }

    @Override
    public Response export(UriInfo uriInfo, RealmModel realm, String format) {
        try (InputStream is = getClass().getResourceAsStream("/wsfed-sp-metadata-template.xml"); BufferedReader br = new BufferedReader(new InputStreamReader(is))) {
            KeyManager keyManager = session.keys();
            String template = br.lines().collect(Collectors.joining("\n"));
            template = template.replace("${idp.entityID}", RealmsResource.realmBaseUrl(uriInfo).build(realm.getName()).toString());
            template = template.replace("${idp.display.name}", RealmsResource.realmBaseUrl(uriInfo).build(realm.getName()).toString());
            template = template.replace("${idp.sso.sp}", getEndpoint(uriInfo, realm));
            template = template.replace("${idp.sso.passive}", getEndpoint(uriInfo, realm));
            template = template.replace("${idp.signing.certificate}", PemUtils.encodeCertificate(keyManager.getActiveKey(realm, KeyUse.SIG, Algorithm.RS256).getCertificate()));
            return Response.ok(template, MediaType.APPLICATION_XML_TYPE).build();
        } catch (Exception ex) {
            throw new IdentityBrokerException("Could not generate SP metadata", ex);
        }
    }

    public String getEndpoint(UriInfo uriInfo, RealmModel realm) {
        return uriInfo.getBaseUriBuilder()
                .path("realms").path(realm.getName())
                .path("broker")
                .path(getConfig().getAlias())
                .path("endpoint")
                .build().toString();
    }

    @Override
    public IdentityProviderDataMarshaller getMarshaller() {
        return new WSFedDataMarshaller();
    }
}
