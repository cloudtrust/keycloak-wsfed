package com.quest.keycloak.broker.wsfed.mappers;

import com.quest.keycloak.broker.wsfed.WSFedEndpoint;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.models.*;
import org.keycloak.saml.processing.core.saml.v2.util.XMLTimeUtil;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.*;

import static org.junit.Assert.*;

import static org.mockito.Mockito.*;

public class UserAttributeMapperTest {
    @Mock KeycloakSession session;
    @Mock RealmModel realm;
    @Mock UserModel user;
    @Mock IdentityProviderMapperModel mapperModel;
    @Mock BrokeredIdentityContext context;

    UserAttributeMapper userAttributeMapper;
    Map<String, String> mapperConfig;
    Map<String, Object> contextData;
    AssertionType assertionType;

    @Before
    public void before() throws Exception {
        MockitoAnnotations.initMocks(this);
        mapperConfig = new HashMap<>();
        mapperConfig.put(UserAttributeMapper.USER_ATTRIBUTE, "user-attribute");
        when(mapperModel.getConfig()).thenReturn(mapperConfig);
        contextData = new HashMap<>();
        assertionType = new AssertionType("12345", XMLTimeUtil.getIssueInstant());
        contextData.put(WSFedEndpoint.WSFED_REQUESTED_TOKEN, assertionType);
        when(context.getContextData()).thenReturn(contextData);
        userAttributeMapper = new UserAttributeMapper();
    }

    @Test
    public void testImportNewUserByName() {
        mapperConfig.put(UserAttributeMapper.ATTRIBUTE_NAME, "attribute-name");
        assertionType.addStatement(Utils.buildAssertionAttributeStatement("attribute-name", null, "name value"));
        userAttributeMapper.importNewUser(session, realm, user, mapperModel, context);

        verify(user, times(1)).setSingleAttribute("user-attribute", "name value");
    }

    @Test
    public void testImportNewUserByFriendlyName() {
        mapperConfig.put(UserAttributeMapper.ATTRIBUTE_FRIENDLY_NAME, "attribute-friendly-name");
        assertionType.addStatement(Utils.buildAssertionAttributeStatement(null, "attribute-friendly-name", "friendly name value"));
        userAttributeMapper.importNewUser(session, realm, user, mapperModel, context);

        verify(user, times(1)).setSingleAttribute("user-attribute", "friendly name value");
    }

    @Test
    public void testImportNewUserByNameAndFriendlyBuNameDoesntMatchFail() {
        mapperConfig.put(UserAttributeMapper.ATTRIBUTE_NAME, "attribute-name-wrong");
        mapperConfig.put(UserAttributeMapper.ATTRIBUTE_FRIENDLY_NAME, "attribute-friendly-name");
        assertionType.addStatement(Utils.buildAssertionAttributeStatement("attribute-name", "attribute-friendly-name", "value"));
        userAttributeMapper.importNewUser(session, realm, user, mapperModel, context);

        verify(user, never()).setSingleAttribute(anyString(), anyString());
    }

    @Test
    public void testImportNewUserByNameAndFriendlyBuFriedlyNameDoesntMatchFail() {
        mapperConfig.put(UserAttributeMapper.ATTRIBUTE_NAME, "attribute-name");
        mapperConfig.put(UserAttributeMapper.ATTRIBUTE_FRIENDLY_NAME, "attribute-friendly-name-wrong");
        assertionType.addStatement(Utils.buildAssertionAttributeStatement("attribute-name", "attribute-friendly-name", "value"));
        userAttributeMapper.importNewUser(session, realm, user, mapperModel, context);

        verify(user, never()).setSingleAttribute(anyString(), anyString());
    }

    @Test
    public void testUpdateBrokeredUser() {
        mapperConfig.put(UserAttributeMapper.ATTRIBUTE_NAME, "attribute-name");
        assertionType.addStatement(Utils.buildAssertionAttributeStatement("attribute-name", null, "name value"));

        assertNotNull(userAttributeMapper.getAttribute(mapperModel, context));
        assertNotEquals(userAttributeMapper.getAttribute(mapperModel, context), user.getFirstAttribute("user-attribute"));
        userAttributeMapper.updateBrokeredUser(session, realm, user, mapperModel, context);
        verify(user, times(1)).setSingleAttribute("user-attribute", "name value");
    }

    @Test
    public void testUpdateBrokeredUserSameValue() {
        when(user.getFirstAttribute("user-attribute")).thenReturn("name value");
        mapperConfig.put(UserAttributeMapper.ATTRIBUTE_NAME, "attribute-name");
        assertionType.addStatement(Utils.buildAssertionAttributeStatement("attribute-name", null, "name value"));

        assertEquals(userAttributeMapper.getAttribute(mapperModel, context), user.getFirstAttribute("user-attribute"));
        userAttributeMapper.updateBrokeredUser(session, realm, user, mapperModel, context);
        verify(user, never()).setSingleAttribute(anyString(), anyString());
    }

    @Test
    public void testUpdateBrokeredUserRemoveAttribute() {
        mapperConfig.put(UserAttributeMapper.ATTRIBUTE_NAME, "attribute-name");
        userAttributeMapper.updateBrokeredUser(session, realm, user, mapperModel, context);

        assertNull(userAttributeMapper.getAttribute(mapperModel, context));
        verify(user, times(1)).removeAttribute("user-attribute");
    }
}
