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

package com.quest.keycloak.protocol.wsfed;

import com.quest.keycloak.common.wsfed.WSFedConstants;
import com.quest.keycloak.common.wsfed.builders.WSFedResponseBuilder;
import com.quest.keycloak.protocol.wsfed.builders.WSFedProtocolParameters;
import com.quest.keycloak.protocol.wsfed.installation.WSFedIDPDescriptorClientInstallation;
import org.jboss.logging.Logger;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.AuthorizationEndpointBase;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.utils.RedirectUtils;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.ErrorPageException;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.sessions.AuthenticationSessionModel;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

/**
 * All protocols added to keycloak have to extend the AuthorizationEndpointBase.
 * <p>
 * In this case, for WS-FED, this class implements parts of the specifications
 * (see http://docs.oasis-open.org/wsfed/federation/v1.2/os/ws-federation-1.2-spec-os.html), namely the single sign-on
 * (see section 13.6) and signout (see section 13.2.4).
 * <p>
 * Note: this part of the protocol is for responding to browser requests, not the SOAP part of the WS protocol.
 * This also means that this part doesn't implement any "server to server" communication. Everything is initiated by the
 * client and handled through the browser.
 * <p>
 * Created on 5/19/15.
 */
public class WSFedService extends AuthorizationEndpointBase {
    protected static final Logger logger = Logger.getLogger(WSFedService.class);

    /**
     * Standard constructor
     * TODO figure out what Eventbuilder does (because of course it's not documented)
     *
     * @param realm The keycloak realm that represents this WSFedService (client service)
     * @param event
     */
    public WSFedService(RealmModel realm, EventBuilder event) {
        super(realm, event);
    }

    /**
     * Method called in case of a GET. Current supports only SIGNIN and SIGNOUT (cleanup handled as signout).
     * WS-Fed protocol makes no difference between GET and POST for these steps.
     * <p>
     * Used if the client uses a 302 to send its message to keycloak
     */
    @GET
    public Response redirectBinding() {
        logger.debug("WS-Fed GET");
        return handleWsFedRequest(false);
    }

    /**
     * Method called in case of a POST. Current supports only SIGNIN and SIGNOUT (cleanup handled as signout)
     * WS-Fed protocol makes no difference between GET and POST for these steps.
     * This method forces a redirection for authentication. This is not required by WS-Fed, but recommended by
     * Keycloak AuthorizationEndpointBase
     */
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response postBinding() {
        logger.debug("WS-Fed POST");
        return handleWsFedRequest(true);
    }

    /**
     * Returns the federation metadata document identifying the endpoint address as a SecurityTokenService
     * (see http://docs.oasis-open.org/wsfed/federation/v1.2/os/ws-federation-1.2-spec-os.html
     * section 3.1.2.2 SecurityTokenServiceType).
     * <p>
     * FIXME replace lazy xml template substitution with JAXB handling .... probably.
     *
     * @return a string containing the xml for the wsfed metadata
     * @throws Exception IOException if there's a problem reading the wsfed-idp-metadata-template.xml
     */
    @GET
    @Path("descriptor")
    @Produces(MediaType.APPLICATION_XML)
    public String getDescriptor() throws Exception {
        return WSFedIDPDescriptorClientInstallation.getIDPDescriptorForClient(session, realm, session.getContext().getUri().getBaseUri());
    }

    /**
     * Makes basic sanity checks on the general state of the connection and the request's parameters.
     * <p>
     * NOTE: Many of the assumptions made in this method only hold true because attributes and pseudonyms are not
     * considered.
     *
     * @param params the WSFedProtocolParameters obtained from the browser request.
     * @return a response corresponding to an error page if the sanity checks fail, and null otherwise
     */
    protected Response basicChecks(WSFedProtocolParameters params) {
        AuthenticationManager.AuthResult authResult = authenticateIdentityCookie();

        try {
            event.event(EventType.LOGIN);
            checkSsl();
            event.event(EventType.LOGIN_ERROR);
            checkRealm();
            event.event(null);
        } catch (ErrorPageException e) {
            return e.getResponse();
        }

        if (params.getWsfed_action() == null) {
            if (authResult != null && authResult.getSession().getState() == UserSessionModel.State.LOGGING_OUT) {
                params.setWsfed_action(UserSessionModel.State.LOGGING_OUT.toString());
            }
        }

        if (params.getWsfed_action() == null) {
            event.event(EventType.LOGIN);
            event.error(Errors.INVALID_REQUEST);
            return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST);
        }

        if (params.getWsfed_realm() == null) {
            if (isSignout(params)) {
                //The spec says that signout doesn't require wtrealm but we generally need a way to identify the client to do SLO properly. So if wtrealm isn't passed get the user session and see if we
                //have one.
                if (authResult != null) {
                    UserSessionModel userSession = authResult.getSession();
                    params.setWsfed_realm(userSession.getNote(WSFedConstants.WSFED_REALM));
                }
            } else { //If it's not a signout event than wtrealm is required
                event.event(EventType.LOGIN);
                event.error(Errors.INVALID_CLIENT);
                return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST);
            }
        }

        return null;
    }

    /**
     * Checks if any of the signout parameters are set, or if the state is "logging out"
     *
     * @param params the WSFedProtocolParameters obtained from the browser request
     * @return true if we are in signout situation
     */
    protected boolean isSignout(WSFedProtocolParameters params) {
        return params.getWsfed_action().compareTo(WSFedConstants.WSFED_SIGNOUT_ACTION) == 0 ||
                params.getWsfed_action().compareTo(WSFedConstants.WSFED_SIGNOUT_CLEANUP_ACTION) == 0 ||
                params.getWsfed_action().compareTo(UserSessionModel.State.LOGGING_OUT.toString()) == 0;
    }

    /**
     * Checks that the client (the resource in this case) meets sanity tests
     * i.e. known by keycloak, is enabled, and does not only have "bearer" tokens (tokens that only carry information)
     *
     * @param client in this case the client is the resource (which is also a client to keycloak)
     * @param params the WSFedProtocolParameters obtained from the browser request
     * @return a response corresponding to an error page if the sanity checks fail, and null otherwise
     */
    protected Response clientChecks(ClientModel client, WSFedProtocolParameters params) {
        if (isSignout(params)) {
            return null; //client checks not required for logout
        }

        if (client == null) {
            event.event(EventType.LOGIN);
            event.error(Errors.CLIENT_NOT_FOUND);
            return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.UNKNOWN_LOGIN_REQUESTER);
        }

        if (!client.isEnabled()) {
            event.event(EventType.LOGIN);
            event.error(Errors.CLIENT_DISABLED);
            return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.LOGIN_REQUESTER_NOT_ENABLED);
        }
        if ((client instanceof ClientModel) && client.isBearerOnly()) {
            event.event(EventType.LOGIN);
            event.error(Errors.NOT_ALLOWED);
            return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.BEARER_ONLY);
        }

        session.getContext().setClient(client);

        return null;
    }

    /**
     * Main method called when a GET or POST is called. Based on the WS-Fed action in the section 13.1.
     * However, only sign-on and sign-out are implemented.
     * Attributes are not implemented (501) and Pseudonym request is completely absent -> a request would return an error
     * <p>
     * TODO figure out what the flow path is
     *
     * @param redirectToAuthentication if set to true, on login the authentication processor will redirect to the "flow path" (whatever that is)
     * @return a javax Response for the web browser.
     */
    public Response handleWsFedRequest(boolean redirectToAuthentication) {
        MultivaluedMap<String, String> requestParams = null;
        if (httpRequest.getHttpMethod().equals(HttpMethod.POST)) {
            requestParams = httpRequest.getFormParameters();
        } else {
            requestParams = session.getContext().getUri().getQueryParameters(true);
        }

        WSFedProtocolParameters params = WSFedProtocolParameters.fromParameters(requestParams);
        Response response = basicChecks(params);
        if (response != null) return response;

        ClientModel client = realm.getClientByClientId(params.getWsfed_realm()); //at this point in a login this should be the resource's realm
        response = clientChecks(client, params);
        if (response != null) return response;

        event.client(client);
        event.realm(realm);

        if (params.getWsfed_action().compareTo(WSFedConstants.WSFED_SIGNIN_ACTION) == 0) {
            return handleLoginRequest(params, client, redirectToAuthentication);
        } else if (params.getWsfed_action().compareTo(WSFedConstants.WSFED_ATTRIBUTE_ACTION) == 0) {
            return Response.status(501).build(); //Not Implemented
        } else if (params.getWsfed_action().compareTo(WSFedConstants.WSFED_SIGNOUT_ACTION) == 0 ||
                params.getWsfed_action().compareTo(WSFedConstants.WSFED_SIGNOUT_CLEANUP_ACTION) == 0) {
            logger.debug("** logout request");
            event.event(EventType.LOGOUT);

            return handleLogoutRequest(params, client);
        } else if (params.getWsfed_action().compareTo(UserSessionModel.State.LOGGING_OUT.toString()) == 0) {
            logger.debug("** logging out request");
            event.event(EventType.LOGOUT);

            return handleLogoutResponse(params, client);
        } else {
            event.event(EventType.LOGIN);
            event.error(Errors.INVALID_TOKEN);
            return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST);
        }
    }

    /**
     * Method called for a login action (wa=wsignin1.0).
     * What this method does in reality is prepare the ClientSessionModel and Loginprotocol (in a separate method for
     * test purposes), and then hand them over to keycloak's AuthorizationEndpointBase's
     * handleBrowserAuthenticationRequest.
     *
     * @param params                   the WSFedProtocolParameters obtained from the browser request
     * @param client                   in this case the client is the resource (which is a client configured in keycloak)
     * @param redirectToAuthentication if set to true, on login the authentication processor will redirect to the "flow path"
     * @return the response generated by keycloak's AuthorizationEndpointBase handleBrowserAuthenticationRequest, or an error page
     */
    protected Response handleLoginRequest(WSFedProtocolParameters params, ClientModel client, boolean redirectToAuthentication) {
        logger.debug("** login request");
        event.event(EventType.LOGIN);

        //Essentially ACS
        String redirect = RedirectUtils.verifyRedirectUri(session.getContext().getUri(), params.getWsfed_reply(), realm, client);

        if (redirect == null && !client.getRedirectUris().isEmpty()) {
            //wreply is optional so if it's not specified use the base url
            redirect = client.getBaseUrl();
        }
        if (redirect == null) {
            event.error(Errors.INVALID_REDIRECT_URI);
            return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_REDIRECT_URI);
        }

        //WS-FED doesn't carry connection state at this point, but a freshness of 0 indicates a demand to re-prompt
        //for authentication (indicating the request is not new), maybe. TODO check logic
        //However, requestState isn't actually used any more :-/
        AuthenticationSessionModel authSession = createAuthenticationSession(client, params.getWsfed_freshness());

        authSession.setProtocol(WSFedLoginProtocol.LOGIN_PROTOCOL);
        authSession.setRedirectUri(redirect);
        authSession.setAction(AuthenticationSessionModel.Action.AUTHENTICATE.name());
        authSession.setClientNote(WSFedConstants.WSFED_CONTEXT, params.getWsfed_context());
        authSession.setClientNote(OIDCLoginProtocol.ISSUER, RealmsResource.realmBaseUrl(session.getContext().getUri()).build(realm.getName()).toString());

        LoginProtocol wsfedProtocol = new WSFedLoginProtocol().setEventBuilder(event).setHttpHeaders(headers).setRealm(realm).setSession(session).setUriInfo(session.getContext().getUri());
        return handleBrowserAuthenticationRequest(authSession, wsfedProtocol, false, redirectToAuthentication);
    }

    protected Response handleLogoutRequest(WSFedProtocolParameters params, ClientModel client) {
        //We either need a client or a reply address to make this work
        if (client == null && params.getWsfed_reply() == null) {
            event.event(EventType.LOGOUT);
            event.error(Errors.INVALID_REQUEST);
            return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST);
        }

        String logoutUrl;
        if (client != null) {
            logoutUrl = RedirectUtils.verifyRedirectUri(session.getContext().getUri(), params.getWsfed_reply(), realm, client);
        } else {
            logoutUrl = RedirectUtils.verifyRealmRedirectUri(session.getContext().getUri(), params.getWsfed_reply(), realm);
        }

        AuthenticationManager.AuthResult authResult = authenticateIdentityCookie();
        if (authResult != null) {
            UserSessionModel userSession = authResult.getSession();
            userSession.setNote(WSFedLoginProtocol.WSFED_LOGOUT_BINDING_URI, logoutUrl);
            userSession.setNote(WSFedLoginProtocol.WSFED_CONTEXT, params.getWsfed_context());
            userSession.setNote(AuthenticationManager.KEYCLOAK_LOGOUT_PROTOCOL, WSFedLoginProtocol.LOGIN_PROTOCOL);

            // remove client from logout requests
            AuthenticatedClientSessionModel clientSession = userSession.getAuthenticatedClientSessions().get(client.getId());
            if (clientSession.getClient().getId().equals(client.getId())) {
                clientSession.setAction(AuthenticationSessionModel.Action.LOGGED_OUT.name());
            }

            event.user(userSession.getUser());
            event.session(userSession);

            logger.debug("browser Logout");
            Response response = AuthenticationManager.browserLogout(session, realm, userSession, session.getContext().getUri(), clientConnection, headers, client.getName());
            event.success();
            return response;
        }

        //This gets called if KC has no session for the user. Essentially they are already logged out?
        WSFedResponseBuilder builder = new WSFedResponseBuilder();
        builder.setMethod(HttpMethod.GET)
                .setContext(params.getWsfed_context())
                .setDestination(logoutUrl);

        return builder.buildResponse(null);
    }

    protected Response handleLogoutResponse(WSFedProtocolParameters params, ClientModel client) {
        AuthenticationManager.AuthResult authResult = authenticateIdentityCookie();
        if (authResult == null) {
            logger.warn("Unknown ws-fed response.");
            event.event(EventType.LOGOUT);
            event.error(Errors.INVALID_TOKEN);
            return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST);
        }

        // assume this is a logout response
        UserSessionModel userSession = authResult.getSession();
        if (userSession.getState() != UserSessionModel.State.LOGGING_OUT) {
            logger.warn("Unknown ws-fed response.");
            logger.warn("UserSession is not tagged as logging out.");
            event.event(EventType.LOGOUT);
            event.error(Errors.INVALID_SAML_LOGOUT_RESPONSE);
            return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST);
        }

        event.user(userSession.getUser());
        event.session(userSession);

        logger.debug("logout response");
        Response response = AuthenticationManager.browserLogout(session, realm, userSession, session.getContext().getUri(), clientConnection, headers, client.getName());
        event.success();
        return response;
    }

    /**
     * The only purpose of this method is to allow us to unit test this class
     *
     * @return
     */
    protected AuthenticationManager.AuthResult authenticateIdentityCookie() {
        return AuthenticationManager.authenticateIdentityCookie(session, realm, false);
    }
}
