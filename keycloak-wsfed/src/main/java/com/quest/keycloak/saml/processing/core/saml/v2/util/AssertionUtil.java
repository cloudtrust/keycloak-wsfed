package com.quest.keycloak.saml.processing.core.saml.v2.util;

import org.keycloak.dom.saml.v1.assertion.SAML11AssertionType;
import org.keycloak.saml.common.PicketLinkLogger;
import org.keycloak.saml.common.PicketLinkLoggerFactory;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.DocumentUtil;
import org.keycloak.saml.common.util.StaxUtil;
import org.keycloak.saml.processing.core.saml.v1.writers.SAML11AssertionWriter;
import org.w3c.dom.Document;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

/**
 * @author <a href="mailto:brat000012001@gmail.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @since 9/25/2017
 */

public class AssertionUtil {
    private static final PicketLinkLogger logger = PicketLinkLoggerFactory.getLogger();
    /**
     * Given {@code AssertionType}, convert it into a DOM Document.
     *
     * @param assertion
     *
     * @return
     *
     * @throws ProcessingException
     */
    public static Document asDocument(SAML11AssertionType assertion) throws ProcessingException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        SAML11AssertionWriter writer = new SAML11AssertionWriter(StaxUtil.getXMLStreamWriter(baos));

        writer.write(assertion);

        try {
            return DocumentUtil.getDocument(new ByteArrayInputStream(baos.toByteArray()));
        } catch (Exception e) {
            throw logger.processingError(e);
        }
    }
}
