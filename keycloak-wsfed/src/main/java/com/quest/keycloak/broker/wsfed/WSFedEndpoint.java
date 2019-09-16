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
import com.quest.keycloak.common.wsfed.parsers.WSTrustParser;
import com.quest.keycloak.common.wsfed.utils.WSFedValidator;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.saml.common.exceptions.ConfigurationException;
import org.keycloak.saml.common.exceptions.NotImplementedException;
import org.keycloak.saml.common.exceptions.ParsingException;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.StringUtil;
import org.keycloak.saml.processing.core.saml.v2.util.XMLTimeUtil;
import org.keycloak.saml.processing.core.util.XMLSignatureUtil;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.ClientSessionCode;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.CommonClientSessionModel;
import org.picketlink.identity.federation.core.wstrust.wrappers.Lifetime;
import org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityTokenResponse;
import org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityTokenResponseCollection;

import javax.ws.rs.*;
import javax.ws.rs.core.*;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author <a href="mailto:kevin.horvatin@software.dell.com">Kevin Horvatin</a>
 * @version $Revision: 1 $
 */
public class WSFedEndpoint {
    public static final String WSFED_REQUESTED_TOKEN = "WSFED_REQUESTED_TOKEN";
    protected static final Logger logger = Logger.getLogger(WSFedEndpoint.class);
    protected RealmModel realm;
    protected EventBuilder event;
    protected WSFedIdentityProviderConfig config;
    protected IdentityProvider.AuthenticationCallback callback;
    protected WSFedIdentityProvider provider;
    protected AuthenticationManager authMgr = new AuthenticationManager();

    @Context
    private UriInfo uriInfo;

    @Context
    private KeycloakSession session;

    @Context
    private ClientConnection clientConnection;

    @Context
    private HttpHeaders headers;

    public WSFedEndpoint(RealmModel realm, WSFedIdentityProvider provider, WSFedIdentityProviderConfig config,
                         IdentityProvider.AuthenticationCallback callback) {
        this.realm = realm;
        this.config = config;
        this.callback = callback;
        this.provider = provider;
    }

    @GET
    public Response redirectBinding(@QueryParam(WSFedConstants.WSFED_ACTION) String wsfedAction,
                                    @QueryParam(WSFedConstants.WSFED_RESULT) String wsfedResult,
                                    @QueryParam(WSFedConstants.WSFED_CONTEXT) String context) {
        return execute(wsfedAction, wsfedResult, context);
    }


    /**
     *
     */
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response postBinding(@FormParam(WSFedConstants.WSFED_ACTION) String wsfedAction,
                                @FormParam(WSFedConstants.WSFED_RESULT) String wsfedResult,
                                @FormParam(WSFedConstants.WSFED_CONTEXT) String context) {
        return execute(wsfedAction, wsfedResult, context);
    }


    protected PublicKey getIDPKey() throws ProcessingException, ConfigurationException {
        X509Certificate certificate = null;
        try {
            certificate = XMLSignatureUtil.getX509CertificateFromKeyInfoString(config.getSigningCertificate().replaceAll("\\s", ""));
        } catch (NullPointerException e) {
            throw new ConfigurationException(e);
        }
        return certificate.getPublicKey();
    }

    protected Response execute(String wsfedAction, String wsfedResult, String context) {
        event = new EventBuilder(realm, session, clientConnection);

        if (context != null) {
            // strip out any additions made for C-BAS, e.g. &username=xxx, etc.
            // otherwise it will choke while trying to process it as a code
            String[] contextParts = context.split("&");
            context = contextParts[0];
        }
        if (wsfedAction == null && config.handleEmptyActionAsLogout()) {
            return handleSignoutResponse(context);
        }
        WSFedValidator wsfedValidator = new WSFedValidator(event, realm);
        Response response = wsfedValidator.basicChecks(wsfedAction, uriInfo, clientConnection, session);
        if (response != null)
            return response;
        if (wsfedResult != null)
            return handleWsFedResponse(wsfedResult, context);
        if (wsfedAction.compareTo(WSFedConstants.WSFED_SIGNOUT_ACTION) == 0)
            return handleSignoutRequest(context);
        if (wsfedAction.compareTo(WSFedConstants.WSFED_SIGNOUT_CLEANUP_ACTION) == 0)
            return handleSignoutResponse(context);

        return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST);
    }

    protected Response handleSignoutRequest(String context) {
        AuthenticationManager.AuthResult result = authMgr.authenticateIdentityCookie(session, realm);

        if (result == null || result.getSession() == null) {
            logger.error("no valid user session");
            event.event(EventType.LOGOUT);
            event.error(Errors.USER_SESSION_NOT_FOUND);
            return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
        }

        List<UserSessionModel> userSessions = session.sessions().getUserSessionByBrokerUserId(realm, result.getSession().getBrokerUserId());
        for (UserSessionModel userSession : userSessions) {
            if (userSession.getState() == UserSessionModel.State.LOGGING_OUT || userSession.getState() == UserSessionModel.State.LOGGED_OUT) {
                continue;
            }
            try {
                AuthenticationManager.backchannelLogout(session, realm, userSession, uriInfo, clientConnection, headers, false);
            } catch (Exception e) {
                logger.warn("failed to do backchannel logout for userSession", e);
            }
        }

        // Send signout to IDP
        WSFedResponseBuilder builder = new WSFedResponseBuilder();
        builder.setMethod(HttpMethod.GET)
                .setAction(WSFedConstants.WSFED_SIGNOUT_ACTION)
                .setRealm(config.getWsFedRealm())
                .setContext(context)
                .setReplyTo(provider.getEndpoint(uriInfo, realm))
                .setDestination(config.getSingleLogoutServiceUrl());

        return builder.buildResponse(null);
    }

    protected Response handleSignoutResponse(String context) {
        AuthenticationManager.AuthResult result = authMgr.authenticateIdentityCookie(session, realm);

        if (result == null || result.getSession() == null) {
            logger.error("no valid user session");
            event.event(EventType.LOGOUT);
            event.error(Errors.USER_SESSION_NOT_FOUND);
            return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
        }

        UserSessionModel userSession = result.getSession();

        if (userSession.getState() != UserSessionModel.State.LOGGING_OUT) {
            logger.error("usersession in different state");
            event.event(EventType.LOGOUT);
            event.error(Errors.USER_SESSION_NOT_FOUND);
            return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.SESSION_NOT_ACTIVE);
        }

        return AuthenticationManager.finishBrowserLogout(session, realm, userSession, uriInfo, clientConnection, headers);
    }

    private Map<String, String> getContextParameters(String context) {
        Map<String, String> map = new HashMap<>();
        if (context == null) {
            return map;
        }
        for (String keyValuePair : context.split("&")) {
            String[] keyValuePairParts = keyValuePair.split("=");
            if (keyValuePairParts.length != 2) {
                continue;
            }
            map.put(keyValuePairParts[0], keyValuePairParts[1]);
        }
        return map;
    }

    protected Response handleLoginResponse(String wsfedResponse, RequestedToken token, String context) throws IdentityBrokerException {
        try {
            BrokeredIdentityContext identity = new BrokeredIdentityContext(token.getId());
            if (context != null) {
                String decodedContext = URLDecoder.decode(context, StandardCharsets.UTF_8.name());
                if (decodedContext.contains("redirectUri=")) {
                    Map<String, String> map = getContextParameters(decodedContext);
                    String redirectUri = URLDecoder.decode(map.get("redirectUri"), StandardCharsets.UTF_8.name());
                    if (decodedContext.contains("&code=")) {
                        //TODO not sure that we indeed have a AuthenticationSessionModel here. It could potentially be a AuthenticatedClientSessionModel. ALSO tabID set to null, but likely broken
                        ClientSessionCode.ParseResult<AuthenticationSessionModel> clientCode = ClientSessionCode.parseResult(map.get("code"), null, this.session, this.session.getContext().getRealm(), this.session.getContext().getClient(), event, AuthenticationSessionModel.class);
                        if (clientCode != null && clientCode.getCode().isValid(CommonClientSessionModel.Action.AUTHENTICATE.name(), ClientSessionCode.ActionType.LOGIN)) {
                            String ACTIVE_CODE = "active_code"; // duplicating because ClientSessionCode.ACTIVE_CODE is private
                            // restore ACTIVE_CODE note because it must have been removed by parse() if code==activeCode
                            clientCode.getClientSession().setClientNote(ACTIVE_CODE, map.get("code"));

                            // set authorization code and redirectUri
                            identity.setCode(map.get("code"));
                            identity.getContextData().put(WSFedConstants.WSFED_CONTEXT, redirectUri);
                        } else {
                            /*
                             * browser session expired, redirect to original URL
                             * which if protected would trigger SSO
                             */
                            return Response.seeOther(new URI(redirectUri)).build();
                        }
                    } else {
                        // only redirectUri (User added by subscription admin)
                        return Response.seeOther(new URI(redirectUri)).build();
                    }
                } else {
                    // regular login with no create user parameters
                    identity.setCode(decodedContext);
                }
            }
            //This token has to be something that the broker code can deserialize. So using our RequestedToken class doesn't work because it can't find the class
            //So instead use the actual token which will be an AssertionType or JWSInput
            identity.getContextData().put(WSFED_REQUESTED_TOKEN, token.getToken());

            identity.setUsername(token.getUsername());

            if (identity.getUsername() == null) {
                throw new IdentityBrokerException("Cannot get a username from the external IdP's token. It must be " +
                        "set for Keycloak to be able to link the external IdP user to a local user");
            }

            if (token.getEmail() != null) {
                identity.setEmail(token.getEmail());
            }

            String givenName;
            if ((givenName = token.getFirstName()) != null) {
                identity.setFirstName(givenName);
            }

            String surName;
            if ((surName = token.getLastName()) != null) {
                identity.setLastName(surName);
            }

            if (config.isStoreToken()) {
                identity.setToken(wsfedResponse);
            }

            String brokerUserId = config.getAlias() + "." + token.getId();
            identity.setBrokerUserId(brokerUserId);
            identity.setIdpConfig(config);
            identity.setIdp(provider);
            if (token.getSessionIndex() != null) {
                identity.setBrokerSessionId(identity.getBrokerUserId() + "." + token.getSessionIndex());
            }

            return callback.authenticated(identity);

        } catch (IdentityBrokerException e) {
            throw e;
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not process response from WS-Fed identity provider.", e);
        }
    }

    protected Response handleWsFedResponse(String wsfedResponse, String context) {
        try {
            RequestSecurityTokenResponse rstr = getWsfedToken(wsfedResponse);
            if (hasExpired(rstr)) {
                event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
                event.error(Errors.EXPIRED_CODE);
                return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_FEDERATED_IDENTITY_ACTION);
            }

            //TODO: Do we need to handle if the IDP sent back more than one token?
            Object rt = rstr.getRequestedSecurityToken().getAny().get(0);
            RequestedToken token = null;

            if (rstr.getTokenType().compareTo(URI.create("urn:oasis:names:tc:SAML:2.0:assertion")) == 0 ||
                    rstr.getTokenType().compareTo(URI.create("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0")) == 0) {
                token = new SAML2RequestedToken(session, wsfedResponse, rt, realm);
            } else if (rstr.getTokenType().compareTo(URI.create("urn:oasis:names:tc:SAML:1.0:assertion")) == 0) {
                token = new SAML11RequestedToken(wsfedResponse, rt);
            } else if (rstr.getTokenType().compareTo(URI.create("urn:ietf:params:oauth:token-type:jwt")) == 0) {
                throw new NotImplementedException("We don't currently support a token type of urn:ietf:params:oauth:token-type:jwt");
            } else {
                throw new NotImplementedException("We don't currently support a token type of " + rstr.getTokenType().toString());
            }

            if (config.isValidateSignature()) {
                Response response = token.validate(getIDPKey(), config, event, session);

                if (response != null) {
                    return response;
                }
            }

            return handleLoginResponse(wsfedResponse, token, context);
        } catch (Exception e) {
            logger.error("assertion parsing failed", e);
            event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
            event.error(Errors.INVALID_SAML_RESPONSE);
            return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_FEDERATED_IDENTITY_ACTION);
        }
    }

    protected boolean hasExpired(RequestSecurityTokenResponse rstr) throws ConfigurationException, DatatypeConfigurationException {
        boolean expiry = false;
        Lifetime lifetime = rstr.getLifetime();
        if (lifetime != null) {
            XMLGregorianCalendar now = XMLTimeUtil.getIssueInstant();
            XMLGregorianCalendar notBefore = lifetime.getCreated();

            if (notBefore != null) {
                // Add in a tiny bit of slop for small clock differences
                notBefore.add(DatatypeFactory.newInstance().newDuration(false, 0, 0, 0, 0, 1, 0));
                logger.trace("RequestSecurityTokenResponse: " + rstr.getContext() + " ::Now=" + now.toXMLFormat() + " ::notBefore="
                        + notBefore.toXMLFormat());
            }

            XMLGregorianCalendar notOnOrAfter = lifetime.getExpires();

            if (notOnOrAfter != null) {
                logger.trace("RequestSecurityTokenResponse: " + rstr.getContext() + " ::Now=" + now.toXMLFormat() + " ::notOnOrAfter=" + notOnOrAfter);
            }

            expiry = !XMLTimeUtil.isValid(now, notBefore, notOnOrAfter);

            if (expiry) {
                logger.info("RequestSecurityTokenResponse has expired with context=" + rstr.getContext());
            }
        }

        return expiry;
    }

    protected RequestSecurityTokenResponse getWsfedToken(String wsfedResponse) throws ParsingException, IOException {
        if (StringUtil.isNullOrEmpty(wsfedResponse)) {
            throw new ParsingException("WSFed response was null");
        }

        WSTrustParser parser = new WSTrustParser();
        try (ByteArrayInputStream bis = new ByteArrayInputStream(wsfedResponse.getBytes())) {
            //TODO: WSTrustParser has a problem when this is a JWT. Not really sure why but guessing it has to do with the BinarySecurityToken.
            Object response = parser.parse(bis);
            RequestSecurityTokenResponse rstr = null;

            if (response instanceof RequestSecurityTokenResponse) {
                rstr = (RequestSecurityTokenResponse) response;
            } else if (response instanceof RequestSecurityTokenResponseCollection) {
                RequestSecurityTokenResponseCollection rstrCollection = (RequestSecurityTokenResponseCollection) response;
                List<RequestSecurityTokenResponse> responses = rstrCollection.getRequestSecurityTokenResponses();
                //RequestSecurityTokenResponseCollection must contain at least one RequestSecurityTokenResponse per the spec
                //TODO: For our needs this should never be more than a single response. But what to do if it for some reason was?
                rstr = responses.get(0);
            }

            return rstr;
        } catch (Exception ex) {
            throw new ParsingException(ex);
        }
    }
}
