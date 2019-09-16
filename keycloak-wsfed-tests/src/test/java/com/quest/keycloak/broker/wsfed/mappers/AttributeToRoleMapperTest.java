package com.quest.keycloak.broker.wsfed.mappers;

import com.quest.keycloak.broker.wsfed.WSFedEndpoint;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.ConfigConstants;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.saml.processing.core.saml.v2.util.XMLTimeUtil;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

import static org.mockito.Mockito.*;

public class AttributeToRoleMapperTest {
    @Mock KeycloakSession session;
    @Mock RealmModel realm;
    @Mock UserModel user;
    @Mock IdentityProviderMapperModel mapperModel;
    @Mock BrokeredIdentityContext context;
    @Mock RoleModel roleModel;

    AttributeToRoleMapper attributeToRoleMapper;
    Map<String, String> mapperConfig;
    Map<String, Object> contextData;
    AssertionType assertionType;

    @Before
    public void before() throws Exception {
        MockitoAnnotations.initMocks(this);
        mapperConfig = new HashMap<>();
        when(mapperModel.getConfig()).thenReturn(mapperConfig);
        contextData = new HashMap<>();
        assertionType = new AssertionType("12345", XMLTimeUtil.getIssueInstant());
        contextData.put(WSFedEndpoint.WSFED_REQUESTED_TOKEN, assertionType);
        when(context.getContextData()).thenReturn(contextData);
        attributeToRoleMapper = new AttributeToRoleMapper();
    }

    @Test
    public void testIsAttributePresentByName() {
        mapperConfig.put(AttributeToRoleMapper.ATTRIBUTE_NAME, "attribute-name");
        mapperConfig.put(AttributeToRoleMapper.ATTRIBUTE_VALUE, "attribute-value");
        assertionType.addStatement(Utils.buildAssertionAttributeStatement("attribute-name", null, "attribute-value"));

        assertTrue(attributeToRoleMapper.isAttributePresent(mapperModel, context));
    }

    @Test
    public void testIsAttributePresentByFriendlyName() {
        mapperConfig.put(AttributeToRoleMapper.ATTRIBUTE_FRIENDLY_NAME, "attribute-friendly-name");
        mapperConfig.put(AttributeToRoleMapper.ATTRIBUTE_VALUE, "attribute-value");
        assertionType.addStatement(Utils.buildAssertionAttributeStatement(null, "attribute-friendly-name", "attribute-value"));

        assertTrue(attributeToRoleMapper.isAttributePresent(mapperModel, context));
    }

    @Test
    public void testImportNewUser() {
        when(KeycloakModelUtils.getRoleFromString(realm, "role-name")).thenReturn(roleModel);
        mapperConfig.put(ConfigConstants.ROLE, "role-name");
        mapperConfig.put(AttributeToRoleMapper.ATTRIBUTE_NAME, "attribute-name");
        mapperConfig.put(AttributeToRoleMapper.ATTRIBUTE_VALUE, "attribute-value");
        assertionType.addStatement(Utils.buildAssertionAttributeStatement("attribute-name", null, "attribute-value"));
        attributeToRoleMapper.importNewUser(session, realm, user, mapperModel, context);

        verify(user, times(1)).grantRole(roleModel);
    }

    @Test
    public void testUpdateBrokeredUser() {
        when(KeycloakModelUtils.getRoleFromString(realm, "role-name")).thenReturn(roleModel);
        mapperConfig.put(ConfigConstants.ROLE, "role-name");
        mapperConfig.put(AttributeToRoleMapper.ATTRIBUTE_NAME, "attribute-name");
        mapperConfig.put(AttributeToRoleMapper.ATTRIBUTE_VALUE, "attribute-value");
        assertionType.addStatement(Utils.buildAssertionAttributeStatement("attribute-name", null, "attribute-value"));

        assertTrue(attributeToRoleMapper.isAttributePresent(mapperModel, context));
        attributeToRoleMapper.updateBrokeredUser(session, realm, user, mapperModel, context);
        verify(user, times(1)).grantRole(roleModel);
    }

    @Test
    public void testUpdateBrokeredUserAttributeNotPresent() {
        when(KeycloakModelUtils.getRoleFromString(realm, "role-name")).thenReturn(roleModel);
        mapperConfig.put(ConfigConstants.ROLE, "role-name");
        mapperConfig.put(AttributeToRoleMapper.ATTRIBUTE_NAME, "attribute-name");
        mapperConfig.put(AttributeToRoleMapper.ATTRIBUTE_VALUE, "attribute-value");

        assertFalse(attributeToRoleMapper.isAttributePresent(mapperModel, context));
        attributeToRoleMapper.updateBrokeredUser(session, realm, user, mapperModel, context);
        verify(user, times(1)).deleteRoleMapping(roleModel);
    }
}
