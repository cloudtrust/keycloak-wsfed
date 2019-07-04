package com.quest.keycloak.integration;

import com.quest.keycloak.broker.wsfed.SAML11RequestedToken;
import com.quest.keycloak.broker.wsfed.SAML2RequestedToken;
import com.quest.keycloak.common.wsfed.WSFedConstants;
import com.quest.keycloak.common.wsfed.parsers.WSTrustParser;
import org.apache.http.util.EntityUtils;
import org.jgroups.util.UUID;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.nodes.Node;
import org.junit.Test;
import org.keycloak.saml.processing.core.saml.v2.util.AssertionUtil;
import org.picketlink.common.exceptions.ParsingException;
import org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityTokenResponse;
import org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityTokenResponseCollection;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.List;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.text.IsEqualIgnoringCase.equalToIgnoringCase;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class WsFedIdpTest extends AbstractWsFedAuthTest {

    private static final String CONSUMER_URL = "http://localhost:4040/";
    private static final String WSFED_LOGIN_URL = KEYCLOAK_URL + "/realms/test-wsfed/protocol/wsfed";
    private static final String SAML2_CLIENT_ID = "wsfed-saml2";
    private static final String SAML1_CLIENT_ID = "wsfed-saml1";

    private static final String IDP_CERT_BASE64 = "MIICozCCAYsCBgFoMq4yNzANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDDAp0ZXN0LXdzZmVkMB4XDTE5MDEwOTEyNTMyM1oXDTI5MDEwOTEyNTUwM1owFTETMBEGA1UEAwwKdGVzdC13c2ZlZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMsWUv1oz/NdPu6lA7O5ZY61MJBIqPIvomVBh6Xkf/v15smS+gZe9o6P/bnaFU+aOKNJ4Ki8qO9HvRQ+jBy+lR1D03fsWVKURcr3QNVSV+v4LNEr75kzzEGof1VMXNtv12l4OJWQ6nN8xREH3anBaBCLhkXgF/nUNmXO74HSmX/OUi9V0WxzmLn93sB68cYV44xICZ/4jiF76Ab66CI5RXxuZYaRMhRz+uBtkofOkkBXXywLHSyrDTkOK92AzoR4VsW0NFK6jcnyH/+1KOneIFenOS2ZVQqs5hD7+Np4b2A77G5BA27ZOki384yin18fuhpiagfd4tt5Ze9aasH2T/UCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAMq3mAHsd3FOJBTKMNI56GABq+941t96xrxutQqfYuKVdrvDaWr7Xs3tR5NqoRkLdH2qTkfiG6EU4UU20TOZcuqI0dFlqRIw2uRoRi030+GLAvclWL1lINwisozy3+WkHMjGWL8Mm8iH9HY63LTZVUwG2nuVG5DcbSr9Us2ncBJEurKBmiM4cxZM7MZCbLuxF1rMEiW2zGv7NcGYh4wV1ShkT5gYXbgUkSI3nElncajl3hmguainqBN0ckUT0W1xH+qWLZsA6kD3e4sgWwTXvDjZ4IcomE4kHGtkMLY0HklI9P2M+DGMF0aivBggfcVj00wBiX54Vi84bWsQB0F6oag==";

    @Test
    public void testNominalCaseWithSaml2() throws Exception {
        String contextUuid = UUID.randomUUID().toString();
        String response = new WsFedClientBuilder()
                .authRequest(new URI(WSFED_LOGIN_URL), CONSUMER_URL, SAML2_CLIENT_ID, contextUuid).build()
                .login().user(bburkeUser).build()
                .executeAndTransform(resp -> EntityUtils.toString(resp.getEntity()));

        String wsFedResponse = checkAutoPostFormContentForResponse(contextUuid, SAML2_CLIENT_ID, response);

        // check WS-Fed response
        assertThat(wsFedResponse, not(nullValue()));
        RequestSecurityTokenResponse rstr = parseRstrToken(wsFedResponse);
        assertThat(rstr.getTokenType().toString(),
                anyOf(
                        equalTo("urn:oasis:names:tc:SAML:2.0:assertion"),
                        equalTo("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0")));

        SAML2RequestedToken token = new SAML2RequestedToken(null, wsFedResponse, rstr.getRequestedSecurityToken().getAny().get(0), null);
        org.w3c.dom.Document d = token.createXmlDocument(wsFedResponse);
        org.w3c.dom.Element assertion = token.extractSamlDocument(d).getDocumentElement();
        assertThat(AssertionUtil.isSignatureValid(assertion, TestCryptoUtil.parseCertificate(IDP_CERT_BASE64).getPublicKey()), equalTo(true));
    }

    @Test
    public void testNominalCaseWithSaml1() throws Exception {
        String contextUuid = UUID.randomUUID().toString();
        String response = new WsFedClientBuilder()
                .authRequest(new URI(WSFED_LOGIN_URL), CONSUMER_URL, SAML1_CLIENT_ID, contextUuid).build()
                .login().user(bburkeUser).build()
                .executeAndTransform(resp -> EntityUtils.toString(resp.getEntity()));

        String wsFedResponse = checkAutoPostFormContentForResponse(contextUuid, SAML1_CLIENT_ID, response);

        // check WS-Fed response
        assertThat(wsFedResponse, not(nullValue()));
        RequestSecurityTokenResponse rstr = parseRstrToken(wsFedResponse);
        assertThat(rstr.getTokenType().toString(), equalTo("urn:oasis:names:tc:SAML:1.0:assertion"));

        SAML11RequestedToken token = new SAML11RequestedToken(wsFedResponse, rstr.getRequestedSecurityToken().getAny().get(0));
        org.w3c.dom.Document d = token.createXmlDocument(wsFedResponse);
        org.w3c.dom.Element assertion = token.extractSamlDocument(d).getDocumentElement();
        assertThat(SAML11RequestedToken.isSignatureValid(assertion, TestCryptoUtil.parseCertificate(IDP_CERT_BASE64).getPublicKey()), equalTo(true));
    }

    /** Parse WS-Fed RequestSecurityToken response message */
    private RequestSecurityTokenResponse parseRstrToken(String tokenString) {
        RequestSecurityTokenResponse rstr = null;
        try (InputStream bis = new ByteArrayInputStream(tokenString.getBytes())) {
            WSTrustParser parser = new WSTrustParser();
            Object response = parser.parse(bis);
            if (response instanceof RequestSecurityTokenResponse) {
                rstr = (RequestSecurityTokenResponse) response;
            }
            else if (response instanceof RequestSecurityTokenResponseCollection) {
                RequestSecurityTokenResponseCollection rstrCollection = (RequestSecurityTokenResponseCollection) response;
                List<RequestSecurityTokenResponse> responses = rstrCollection.getRequestSecurityTokenResponses();
                //RequestSecurityTokenResponseCollection must contain at least one RequestSecurityTokenResponse per the spec
                rstr = responses.get(0);
            }
        }
        catch (IOException | ParsingException ex) {
            fail("Error when parsing the token");
            ex.printStackTrace();
        }
        return rstr;
    }

    /** Check content of the autopost form generated by the IdP for posting the response to the client */
    private String checkAutoPostFormContentForResponse(String contextUuid, String clientId, String response) {
        Document doc = Jsoup.parse(response);
        // check autopost of the form
        assertThat(doc.body().attr("Onload"), containsString("document.forms[0].submit()"));
        // check form content
        String wsFedResponse = null;
        Element form = doc.selectFirst("form");
        assertThat(form, not(nullValue()));
        assertThat(form.attr("ACTION"), equalTo(CONSUMER_URL));
        assertThat(form.childNodeSize(), equalTo(5));

        for (Node input : form.childNodes()) {
            if ("noscript".equalsIgnoreCase(input.nodeName())) {
                // check that there is a button for manual posting of the form
                for (Node elements : input.childNodes()) {
                    if ("p".equalsIgnoreCase(elements.nodeName())) {
                        // skip, nothing to check in the message
                    }
                    else if ("input".equalsIgnoreCase(elements.nodeName())) {
                        assertThat(elements.attr("type"), equalToIgnoringCase("submit"));
                    }
                    else {
                        fail("Unexpected field in form");
                    }
                }
            }
            else {
                switch (input.attr("name")) {
                    case "wa":
                        assertThat(input.attr("value"), equalTo(WSFedConstants.WSFED_SIGNIN_ACTION));
                        break;
                    case "wctx":
                        assertThat(input.attr("value"), equalTo(contextUuid));
                        break;
                    case "wresult":
                        wsFedResponse = input.attr("value");
                        assertThat(wsFedResponse, not(nullValue()));
                        break;
                    case "wtrealm":
                        assertThat(input.attr("value"), equalTo(clientId));
                        break;
                    default:
                        fail("Unexpected field in form");
                }
            }
        }
        return wsFedResponse;
    }

}
