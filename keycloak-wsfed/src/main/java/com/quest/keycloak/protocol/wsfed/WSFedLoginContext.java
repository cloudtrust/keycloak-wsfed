package com.quest.keycloak.protocol.wsfed;

import com.quest.keycloak.protocol.wsfed.builders.RequestSecurityTokenResponseBuilder;

import org.keycloak.dom.saml.common.CommonAssertionType;
import org.keycloak.services.managers.ClientSessionCode;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;

public class WSFedLoginContext {
    private UserSessionModel userSession;
    private ClientSessionContext clientSessionCtx;
    private ClientSessionCode<AuthenticatedClientSessionModel> accessCode;
    private CommonAssertionType samlAssertion;
    private RequestSecurityTokenResponseBuilder builder = new RequestSecurityTokenResponseBuilder();

    public WSFedLoginContext(KeycloakSession session, RealmModel realm, UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        this.userSession = userSession;
        this.clientSessionCtx = clientSessionCtx;
        this.accessCode = new ClientSessionCode<>(session, realm, clientSessionCtx.getClientSession());
    }

    public UserSessionModel getUserSession() {
        return this.userSession;
    }

    public ClientSessionContext getClientSessionContext() {
        return this.clientSessionCtx;
    }

    public AuthenticatedClientSessionModel getClientSession() {
        return this.clientSessionCtx.getClientSession();
    }

    public ClientModel getClient() {
        return this.getClientSessionContext().getClientSession().getClient();
    }

    public ClientSessionCode<AuthenticatedClientSessionModel> getAccessCode() {
        return this.accessCode;
    }

    public void setSamlAssertion(CommonAssertionType samlAssertion) {
        this.samlAssertion = samlAssertion;
    }

    public CommonAssertionType getSamlAssertion() {
        return this.samlAssertion;
    }

    public RequestSecurityTokenResponseBuilder getBuilder() {
        return this.builder;
    }
}
