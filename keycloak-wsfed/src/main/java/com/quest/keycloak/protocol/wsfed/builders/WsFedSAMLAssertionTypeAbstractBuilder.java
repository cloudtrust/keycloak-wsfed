/*
 * Copyright 2016 Analytical Graphics, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package com.quest.keycloak.protocol.wsfed.builders;

import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.services.managers.ClientSessionCode;
import org.keycloak.services.resources.RealmsResource;

import javax.ws.rs.core.UriInfo;

/**
 * @author <a href="mailto:brat000012001@gmail.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @date 10/4/2016
 */

public abstract class
WsFedSAMLAssertionTypeAbstractBuilder<T extends WsFedSAMLAssertionTypeAbstractBuilder> {

    public static final String WSFED_NAME_ID = "WSFED_NAME_ID";
    public static final String WSFED_NAME_ID_FORMAT = "WSFED_NAME_ID_FORMAT";
    public static final String SAML_NAME_ID_FORMAT_ATTRIBUTE = "saml_name_id_format";
    public static final String SAML_DEFAULT_NAMEID_FORMAT = JBossSAMLURIConstants.NAMEID_FORMAT_UNSPECIFIED.get();
    public static final String SAML_FORCE_NAME_ID_FORMAT_ATTRIBUTE = "saml_force_name_id_format";
    public static final String SAML_PERSISTENT_NAME_ID_FOR = "saml.persistent.name.id.for";

    protected UserSessionModel userSession;
    protected AuthenticatedClientSessionModel clientSession;
    protected ClientSessionCode<?> accessCode;
    protected RealmModel realm;
    protected KeycloakSession session;
    protected UriInfo uriInfo;

    protected abstract T getThis();

    public UserSessionModel getUserSession() {
        return userSession;
    }

    public T setUserSession(UserSessionModel userSession) {
        this.userSession = userSession;
        return getThis();
    }

    public AuthenticatedClientSessionModel getClientSession() {
        return clientSession;
    }

    public T setClientSession(AuthenticatedClientSessionModel clientSession) {
        this.clientSession = clientSession;
        return getThis();
    }

    public ClientSessionCode getAccessCode() {
        return accessCode;
    }

    public T setAccessCode(ClientSessionCode accessCode) {
        this.accessCode = accessCode;
        return getThis();
    }

    public RealmModel getRealm() {
        return realm;
    }

    public T setRealm(RealmModel realm) {
        this.realm = realm;
        return getThis();
    }

    public KeycloakSession getSession() {
        return session;
    }

    public T setSession(KeycloakSession session) {
        this.session = session;
        return getThis();
    }

    public UriInfo getUriInfo() {
        return uriInfo;
    }

    public T setUriInfo(UriInfo uriInfo) {
        this.uriInfo = uriInfo;
        return getThis();
    }

    protected String getResponseIssuer(RealmModel realm) {
        return RealmsResource.realmBaseUrl(uriInfo).build(realm.getName()).toString();
    }
}
