/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
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
 */

package com.quest.keycloak.protocol.wsfed.installation;

import com.quest.keycloak.protocol.wsfed.WSFedLoginProtocol;
import org.keycloak.Config;
import org.keycloak.common.util.PemUtils;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.*;
import org.keycloak.protocol.ClientInstallationProvider;
import org.keycloak.services.resources.RealmsResource;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class WSFedIDPDescriptorClientInstallation implements ClientInstallationProvider {

    /**
     * Returns the federation metadata document identifying the endpoint address as a SecurityTokenService
     * (see http://docs.oasis-open.org/wsfed/federation/v1.2/os/ws-federation-1.2-spec-os.html
     * section 3.1.2.2 SecurityTokenServiceType).
     *
     * FIXME replace lazy xml template substitution with JAXB handling .... probably.
     *
     * @return a string containing the xml for the wsfed metadata
     * @throws Exception IOException if there's a problem reading the wsfed-idp-metadata-template.xml
     */
    public static String getIDPDescriptorForClient(KeycloakSession session, RealmModel realm, URI uri) throws Exception{
        KeyManager keyManager = session.keys();
        KeyWrapper activeKey = keyManager.getActiveKey(realm, KeyUse.SIG, Algorithm.RS256);
        InputStream is = WSFedIDPDescriptorClientInstallation.class.getClassLoader().getResourceAsStream("wsfed-idp-metadata-template.xml");
        String template = "Error getting descriptor";
        try(BufferedReader br = new BufferedReader(new InputStreamReader(is))){
            template = br.lines().collect(Collectors.joining("\n"));
            template = template.replace("${idp.entityID}", RealmsResource.realmBaseUrl(UriBuilder.fromUri(uri)).build(realm.getName()).toString());
            template = template.replace("${idp.sso.sts}", RealmsResource.protocolUrl(UriBuilder.fromUri(uri)).build(realm.getName(), WSFedLoginProtocol.LOGIN_PROTOCOL).toString());
            template = template.replace("${idp.sso.passive}", RealmsResource.protocolUrl(UriBuilder.fromUri(uri)).build(realm.getName(), WSFedLoginProtocol.LOGIN_PROTOCOL).toString());
            template = template.replace("${idp.signing.certificate}", PemUtils.encodeCertificate(activeKey.getCertificate()));
        }
        return template;
    }

    @Override
    public Response generateInstallation(KeycloakSession session, RealmModel realm, ClientModel client, URI serverBaseUri) {
        String descriptor = null;
        try {
            descriptor = getIDPDescriptorForClient(session, realm, serverBaseUri);
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }
        return Response.ok(descriptor, MediaType.TEXT_PLAIN_TYPE).build();
    }

    @Override
    public String getProtocol() {
        return WSFedLoginProtocol.LOGIN_PROTOCOL;
    }

    @Override
    public String getDisplayType() {
        return "WSFed Metadata IDP Descriptor";
    }

    @Override
    public String getHelpText() {
        return "WSFed Metadata.";
    }

    @Override
    public String getFilename() {
        return "wsfed-idp-metadata.xml";
    }

    public String getMediaType() {
        return MediaType.APPLICATION_XML;
    }

    @Override
    public boolean isDownloadOnly() {
        return false;
    }

    @Override
    public void close() {

    }

    @Override
    public ClientInstallationProvider create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getId() {
        return "wsfed-idp-descriptor";
    }
}
