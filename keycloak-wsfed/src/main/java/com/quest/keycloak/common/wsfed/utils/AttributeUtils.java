package com.quest.keycloak.common.wsfed.utils;

import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType.ASTChoiceType;
import org.keycloak.dom.saml.v2.assertion.AttributeType;

import java.util.List;
import java.util.function.Predicate;

public class AttributeUtils {
    public static List<Object> findAttributeValue(AssertionType assertion, String name, String friendly, Predicate<? super AttributeType> predicate) {
        for (AttributeStatementType statement : assertion.getAttributeStatements()) {
            AttributeType res = statement.getAttributes().stream()
                    .map(ASTChoiceType::getAttribute)
                    .filter(a -> filterAttribute(a, name, friendly) && predicate.test(a))
                    .findFirst()
                    .orElse(null);
            if (res!=null) {
                return res.getAttributeValue();
            }
        }

        return null;
    }

    private static boolean filterAttribute(AttributeType attr, String name, String friendly) {
        if (name != null && !name.equals(attr.getName())) {
            return false;
        }
        return friendly == null || friendly.equals(attr.getFriendlyName());
    }
}
