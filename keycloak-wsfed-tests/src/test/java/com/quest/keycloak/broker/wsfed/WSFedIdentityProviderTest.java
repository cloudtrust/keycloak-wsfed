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

import com.quest.keycloak.common.wsfed.MockHelper;
import com.quest.keycloak.common.wsfed.TestHelpers.*;
import com.quest.keycloak.common.wsfed.WSFedConstants;

import io.cloudtrust.keycloak.exceptions.CtRuntimeException;

import org.apache.http.HttpStatus;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.broker.provider.util.IdentityBrokerState;
import org.keycloak.common.util.PemUtils;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.services.resources.RealmsResource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.Response;

import static com.quest.keycloak.common.wsfed.TestHelpers.*;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.*;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

public class WSFedIdentityProviderTest {
    @Mock
    private EventBuilder event;
    @Mock
    private WSFedIdentityProviderConfig config;

    private MockHelper mockHelper;
    private WSFedIdentityProvider identityProvider;

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        mockHelper = getMockHelper().initializeMockValues();

        doReturn("idpAlias").when(config).getAlias();
        doReturn("https://destinationUrl").when(config).getSingleSignOnServiceUrl();
        doReturn("https://realm").when(config).getWsFedRealm();

        identityProvider = spy(new WSFedIdentityProvider(mockHelper.getSession(), config));
    }

    @Test
    public void testCallback() throws Exception {
        IdentityProvider.AuthenticationCallback callback = mock(IdentityProvider.AuthenticationCallback.class);
        Object obj = identityProvider.callback(mockHelper.getRealm(), callback, event);

        assertTrue(obj instanceof WSFedEndpoint);
    }

    @Test
    public void testPerformLoginException() throws Exception {
        doThrow(new CtRuntimeException("Message")).when(config).getWsFedRealm();

        expectedException.expect(IdentityBrokerException.class);
        expectedException.expectMessage(equalTo("Could not create authentication request."));

        identityProvider.performLogin(mock(AuthenticationRequest.class));
    }

    @Test
    public void testPerformLogin() throws Exception {
        AuthenticationRequest request = mock(AuthenticationRequest.class);
        doReturn("https://redirectUri").when(request).getRedirectUri();
        when(request.getState()).thenReturn(mock(IdentityBrokerState.class));
        when(request.getState().getEncoded()).thenReturn("context");
        Response response = identityProvider.performLogin(request);
        Document doc = responseToDocument(response);

        assertFormAction(doc, HttpMethod.GET, config.getSingleSignOnServiceUrl());
        assertInputNode(doc, WSFedConstants.WSFED_ACTION, WSFedConstants.WSFED_SIGNIN_ACTION);
        assertInputNode(doc, WSFedConstants.WSFED_REALM, config.getWsFedRealm());
        assertInputNode(doc, WSFedConstants.WSFED_REPLY, request.getRedirectUri());
        assertInputNode(doc, WSFedConstants.WSFED_CONTEXT, request.getState().getEncoded());
        assertInputNodeMissing(doc, WSFedConstants.WSFED_RESULT);
    }

    @Test
    public void testRetrieveToken() throws Exception {
        FederatedIdentityModel identity = mock(FederatedIdentityModel.class);
        doReturn("token").when(identity).getToken();

        Response response = identityProvider.retrieveToken(mockHelper.getSession(), identity);
        assertEquals(HttpStatus.SC_OK, response.getStatus());
        assertEquals(identity.getToken(), response.getEntity());
    }

    @Test
    public void testGetEndpoint() throws Exception {
        String endpoint = identityProvider.getEndpoint(mockHelper.getUriInfo(), mockHelper.getRealm());

        assertEquals(String.format("%s/realms/%s/broker/%s/endpoint", mockHelper.getBaseUri(), mockHelper.getRealmName(), config.getAlias()), endpoint);
    }

    @Test
    public void testKeycloakInitiatedBrowserLogoutNoSLO() throws Exception {
        Response response = identityProvider.keycloakInitiatedBrowserLogout(mockHelper.getSession(), mockHelper.getUserSessionModel(), mockHelper.getUriInfo(), mockHelper.getRealm());
        assertNull(response);
    }

    @Test
    public void testKeycloakInitiatedBrowserBackchannel() throws Exception {
        doReturn("https://slo").when(config).getSingleLogoutServiceUrl();
        doReturn(true).when(config).isBackchannelSupported();
        doNothing().when(identityProvider).backchannelLogout(mockHelper.getSession(), mockHelper.getUserSessionModel(), mockHelper.getUriInfo(), mockHelper.getRealm());

        Response response = identityProvider.keycloakInitiatedBrowserLogout(mockHelper.getSession(), mockHelper.getUserSessionModel(), mockHelper.getUriInfo(), mockHelper.getRealm());

        assertNull(response);
        verify(identityProvider, times(1)).backchannelLogout(eq(mockHelper.getSession()), eq(mockHelper.getUserSessionModel()), eq(mockHelper.getUriInfo()), eq(mockHelper.getRealm()));
    }

    @Test
    public void testKeycloakInitiatedBrowser() throws Exception {
        doReturn("https://slo").when(config).getSingleLogoutServiceUrl();
        doReturn(false).when(config).isBackchannelSupported();

        Response response = identityProvider.keycloakInitiatedBrowserLogout(mockHelper.getSession(), mockHelper.getUserSessionModel(), mockHelper.getUriInfo(), mockHelper.getRealm());
        Document doc = responseToDocument(response);

        assertFormAction(doc, HttpMethod.GET, config.getSingleLogoutServiceUrl());
        assertInputNode(doc, WSFedConstants.WSFED_ACTION, WSFedConstants.WSFED_SIGNOUT_ACTION);
        assertInputNode(doc, WSFedConstants.WSFED_REALM, config.getWsFedRealm());
        assertInputNode(doc, WSFedConstants.WSFED_REPLY, identityProvider.getEndpoint(mockHelper.getUriInfo(), mockHelper.getRealm()));
        assertInputNode(doc, WSFedConstants.WSFED_CONTEXT, mockHelper.getUserSessionModel().getId());
        assertInputNodeMissing(doc, WSFedConstants.WSFED_RESULT);
    }

    @Test
    public void testExport() throws Exception {
        Response response = identityProvider.export(mockHelper.getUriInfo(), mockHelper.getRealm(), null);
        assertEquals(HttpStatus.SC_OK, response.getStatus());
        Document doc = responseToDocument(response);

        Element root = doc.getDocumentElement();
        assertEquals(RealmsResource.realmBaseUrl(mockHelper.getUriInfo()).build(mockHelper.getRealmName()).toString(), root.getAttribute("entityID"));

        WSFedNamespaceContext nsContext = new WSFedNamespaceContext("urn:oasis:names:tc:SAML:2.0:metadata");

        Node node = assertNode(doc, "/ns:EntityDescriptor/ns:RoleDescriptor", nsContext);
        assertEquals(RealmsResource.realmBaseUrl(mockHelper.getUriInfo()).build(mockHelper.getRealmName()).toString(), node.getAttributes().getNamedItem("ServiceDisplayName").getTextContent());

        node = assertNode(doc, "/ns:EntityDescriptor/ns:RoleDescriptor/ns:KeyDescriptor/dsig:KeyInfo/dsig:X509Data/dsig:X509Certificate", nsContext);
        assertEquals(PemUtils.encodeCertificate(mockHelper.getActiveKey().getCertificate()), node.getTextContent().trim());

        node = assertNode(doc, "/ns:EntityDescriptor/ns:RoleDescriptor/fed:ApplicationServiceEndpoint/wsa:EndpointReference/wsa:Address", nsContext);
        assertEquals(identityProvider.getEndpoint(mockHelper.getUriInfo(), mockHelper.getRealm()), node.getTextContent());

        node = assertNode(doc, "/ns:EntityDescriptor/ns:RoleDescriptor/fed:PassiveRequestorEndpoint/wsa:EndpointReference/wsa:Address", nsContext);
        assertEquals(identityProvider.getEndpoint(mockHelper.getUriInfo(), mockHelper.getRealm()), node.getTextContent());
    }
}