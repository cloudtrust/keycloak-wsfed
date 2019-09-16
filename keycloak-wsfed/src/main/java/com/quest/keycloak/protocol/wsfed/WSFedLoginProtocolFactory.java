package com.quest.keycloak.protocol.wsfed;

import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.LoginProtocol;

public class WSFedLoginProtocolFactory extends AbstractWSFedLoginProtocolFactory {
    @Override
    public LoginProtocol create(KeycloakSession session) {
        return new WSFedLoginProtocol().setSession(session);
    }
}
