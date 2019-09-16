package com.quest.keycloak.integration;

import com.quest.keycloak.common.wsfed.WSFedConstants;
import com.quest.keycloak.protocol.wsfed.builders.RequestSecurityTokenResponseBuilder;
import com.quest.keycloak.protocol.wsfed.builders.SAML11AssertionTypeBuilder;
import com.quest.keycloak.protocol.wsfed.builders.SAML2AssertionTypeBuilder;
import org.apache.http.util.EntityUtils;
import org.jgroups.util.UUID;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.nodes.Node;
import org.junit.Test;
import org.keycloak.dom.saml.v1.assertion.SAML11AssertionType;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;

import java.io.IOException;
import java.net.URI;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.text.IsEqualIgnoringCase.equalToIgnoringCase;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;


public class WsFedBrokerTest extends AbstractWsFedAuthTest {

    // data for triggering the authentication process
    private static final String WSFED_LOGIN_URL = KEYCLOAK_URL + "/realms/test-wsfed/protocol/wsfed";
    private static final String WSFED_BROKER_LOGIN_URL = KEYCLOAK_URL + "/realms/test-wsfed/broker/wsfed/endpoint";
    private static final String WSFED_BROKER_CLIENT_ID = "wsfed";
    private static final String CLIENT_ID = "wsfed-saml2";

    // external IDP
    private static final String DUMMY_IDP_URL = "http://localhost:4040/auth/realms/master/protocol/wsfed";
    private static final String DUMMY_IDP_CLIENT_ID = "test-broker";

    private static final String DUMMY_IDP_ISSUER = "http://localhost:4040/auth/realms/master";

    private static final String IDP_PRIVATE_KEY = "MIIEogIBAAKCAQEAyxZS/WjP810+7qUDs7lljrUwkEio8i+iZUGHpeR/+/XmyZL6Bl72jo/9udoVT5o4o0ngqLyo70e9FD6MHL6VHUPTd+xZUpRFyvdA1VJX6/gs0SvvmTPMQah/VUxc22/XaXg4lZDqc3zFEQfdqcFoEIuGReAX+dQ2Zc7vgdKZf85SL1XRbHOYuf3ewHrxxhXjjEgJn/iOIXvoBvroIjlFfG5lhpEyFHP64G2Sh86SQFdfLAsdLKsNOQ4r3YDOhHhWxbQ0UrqNyfIf/7Uo6d4gV6c5LZlVCqzmEPv42nhvYDvsbkEDbtk6SLfzjKKfXx+6GmJqB93i23ll71pqwfZP9QIDAQABAoIBAH3js8QUIbvZFHa4YagaB8NDu/vknp2qO3+K9Hw4PcHBN7PCYSxr12ieB4kaj9VNY0iNNi9C63GQRbvz3cS/uw1uCvsuzlvrP6xGQrE5nvjOWXG8S4TrX/VfbrdAY9s+5AgkFudX8o1uTXZ2Ksjc9BY1dyF/fT1HeAT6Fuuh0bcv4YQ3UAvsMoNc6xuJR345kY+ltMQgLKpxQ73m9A7kPAYi6X1jbwxWgJwJ3SQ/N7GS0nsDfsuJ3t7IcPYij7cmO2KvqonYYf4BMSi/p/PE2110QdGaYCGaPnVFx7OzCS/bQPklLy0TfvzbOpFVLU5cHR9kQ/Hcf6hoTmhnJeMQKaECgYEA990NNqB+m+/6gFo7cYbMVlR9XLbmFduKmUFHjoK/9V1M/FXVzDvmnc5fPgzMvbgaNJlvVSGoL8+WZpHrOV37pSTlo6Voybhxg6NsI+smDnMGqgQym2PqC/SIMbs0JdEBzFMjU5YzyLrDi1+oDESBVLldkEpUxzHmbJ9dvhg3vr0CgYEA0cD9eENGa2PjQM300j1aM58NpuGEWKK23Boko6+XZAg5jfBkz9uuO5MO3uyyfoR63uEwWQJ7I8iP+fwufydLRHxr5onfrXS84+iVdyHQQR1mbp8YCIPq5dw5uM7uGhc2IzqdyfITNazReyvaOYynsA/G7fR0/YKX0IsXiT2kJZkCgYAxP+0GM7G0jmR56HPzRNOJO9SE/ZqOMUdC2GO9f2FhAZ7wbKXEpQpXxM/L5oMwF0qttOcYRU3D4j2CN/BDP9dmowQ2FgHSQyHbBDfSk0DGkjh6w8bCdYHlyjrdltLvyK3QyZw1WZ0Ef4enQ+SCO4JvMT3UE9Dwm4urfacExI8fCQKBgBUr7Kmx6K64Q1zsLPT3ml4xhLg+dRRZQCnRPbeD5r0DE4QfKp3MZ7a9rjeUHqQkjR5oDnA9jt5axSWPbcYJ2lAMWvvHGNuyN8qtVEDVGecop4ks58kcP5557x2XTXM2upEtvnV+yK+XRQGwuHMsnlRoE0U7cn+QKfCzyWlh3mqpAoGACvEFoFKru/3EPuiSLdk1nzDtyDfGJ381gjNzAbWJdBWpudf7RttmPM+EWUenhHa7LG67Y0GoRlM691L7S6ewTGWiYc0ad351v1LjQjHR9aVDdZrgKW13JGTx8Rp7GE8e2tTVOq/TYUT7fXFM+YRD4JUckF7+re6HRSnoH9vNpTE=";
    private static final String IDP_CERTIFICATE = "MIICozCCAYsCBgFoMq4yNzANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDDAp0ZXN0LXdzZmVkMB4XDTE5MDEwOTEyNTMyM1oXDTI5MDEwOTEyNTUwM1owFTETMBEGA1UEAwwKdGVzdC13c2ZlZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMsWUv1oz/NdPu6lA7O5ZY61MJBIqPIvomVBh6Xkf/v15smS+gZe9o6P/bnaFU+aOKNJ4Ki8qO9HvRQ+jBy+lR1D03fsWVKURcr3QNVSV+v4LNEr75kzzEGof1VMXNtv12l4OJWQ6nN8xREH3anBaBCLhkXgF/nUNmXO74HSmX/OUi9V0WxzmLn93sB68cYV44xICZ/4jiF76Ab66CI5RXxuZYaRMhRz+uBtkofOkkBXXywLHSyrDTkOK92AzoR4VsW0NFK6jcnyH/+1KOneIFenOS2ZVQqs5hD7+Np4b2A77G5BA27ZOki384yin18fuhpiagfd4tt5Ze9aasH2T/UCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAMq3mAHsd3FOJBTKMNI56GABq+941t96xrxutQqfYuKVdrvDaWr7Xs3tR5NqoRkLdH2qTkfiG6EU4UU20TOZcuqI0dFlqRIw2uRoRi030+GLAvclWL1lINwisozy3+WkHMjGWL8Mm8iH9HY63LTZVUwG2nuVG5DcbSr9Us2ncBJEurKBmiM4cxZM7MZCbLuxF1rMEiW2zGv7NcGYh4wV1ShkT5gYXbgUkSI3nElncajl3hmguainqBN0ckUT0W1xH+qWLZsA6kD3e4sgWwTXvDjZ4IcomE4kHGtkMLY0HklI9P2M+DGMF0aivBggfcVj00wBiX54Vi84bWsQB0F6oag==";

    private static final String IDP_WRONG_PRIVATE_KEY = "MIIEpQIBAAKCAQEAofs6xpjJgm9Nlw9gRlhWe/QXyPMoi0RewQ1xBLf5yr1n8EDwM70Zjs2RovYz9Oet1FjtIDBYG3DDCVTj2w9Tb1VQ8FmErZm3Q0O4nweGjwoSzbtDp0frSI+M2GXrSif2Dx2zil4HsCmuroc8ZsedcNMfMRJ8rB4CeTgfqospbR8W2W7vlPBbZGYhc3DJCJazqUEvJqD664S8b6GV0SU1Te8jCav0ujmr2RCvZjWKxRXsK4VMneRwxBBCiR/Fq9Rdn6tWgBBaxfw2Sf97Hjg9ouk6+Dtjt13N4I6EUAMag/5iYrLCc7lrkj8iApylXxflPeBoxDy9wyp7GVQ5BDfG0QIDAQABAoIBAQCJWrUTdLnjXiiIQOSdogjsIScOIost1TMYNyKwIqWxsnzxsM8+wEps2op1ipqyQMcZerLRCc2crzjjr9Vri4pvrQPuW6pzXxaU9lcWm1YR8zPQusv6jLTKGdgQJBSqFErFtKTrXyLb0eyrWEfyy7AI3S3k+c04UlY8nkfT4R+mxE3AlzVzw8iCMdQzofGfNqzUOashQpQir4gmk9yHQtnlMC4wbDjVgAi1vIAwx1rBs7Xvy2ivkmv5+Slcdq6ZkiIF+j3Kf+XnYiCthb47dpCIdSRD+/fuCAJUn2CpsH44Du9DIer3JRZz/R9MYGrc1wRaYOvw49wPSMm+E1DdhvGxAoGBAM7ps6Bp0KAcVO8yBLYVsge2FhyCi3Ek6kUOAVWDRYpW2eqZHtMFD1hC2J2jtD5g8G+EA+gtFkBNDtS8RlhY2ZlhAwftAXJ72AQeEUUbkHCvWFo+w2YqfjPZhpnwVuDsyaONhmbDOT1ZxdjZzJu2k4VN1PuQQ8b8iO1MmMHeS8CtAoGBAMhou3FRJAhnj4Ue55MVfw42dV/4tAi3pb5yNtDfAF1LPC0lbipM2I8o6L2BL61RQxOUw67cDy9tM8NfjdVNVnds5Ge0UtafR5HF5LahBm2tt9+jArxRH0M3+hXYb/xIumOo1Gspnt3dEDMjRuGPx8ueX7AsiKpnN1qzKmfDUc81AoGATN/dQgMuZN5B3CDMSU5kN6M6Mdt6rU3W0FM0wa2k/5HnItdC8YnWuqcTTfZNeEOR8QyuWuutcbRvhzBwPlC8f9TgSGiQ+hTzHAyDxBZKouMyw0zAUkwFWYQ/EyCNVsIC5IYnYjS0JowdCsVY1J2Pz54sPE7ML7kRsoCb3KOXp30CgYEApZHhSj0/B7KHX/OoXlvkHFnhnuhZ1NnklPLHVsjmBC2kCahi24+hWqTxo56XRRld0U+WW2BzKzuNCFxpUVATn5bXHNZdmfL9rfFQg5GFPhfHUXvbRrm+mkok0ud9nXB4jN1uoRpBpgp818LNTIz9A7xUUbh5ME8V7FkZL6CudgECgYEApIUuXYdRyuMGOSc4f9ND2YlyCFFu38KmE2ERKYRYcRX9iiJOMmymgUUKON1TADg4WshyNAo6X/BQV/P6eKtGqdaDHeAcL3tCoxb/eMQ1+dK3dr2SJ1Ybx1E0oU5GRlPCaEKhG1TYfyAUo2Km+quM8PQfSm06mWnenCX+s+znDYo=";
    private static final String IDP_WRONG_CERTIFICATE = "MIICmzCCAYMCBgFnyvM1XDANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0ZXIwHhcNMTgxMjIwMDkyODE1WhcNMjgxMjIwMDkyOTU1WjARMQ8wDQYDVQQDDAZtYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCh+zrGmMmCb02XD2BGWFZ79BfI8yiLRF7BDXEEt/nKvWfwQPAzvRmOzZGi9jP0563UWO0gMFgbcMMJVOPbD1NvVVDwWYStmbdDQ7ifB4aPChLNu0OnR+tIj4zYZetKJ/YPHbOKXgewKa6uhzxmx51w0x8xEnysHgJ5OB+qiyltHxbZbu+U8FtkZiFzcMkIlrOpQS8moPrrhLxvoZXRJTVN7yMJq/S6OavZEK9mNYrFFewrhUyd5HDEEEKJH8Wr1F2fq1aAEFrF/DZJ/3seOD2i6Tr4O2O3Xc3gjoRQAxqD/mJissJzuWuSPyICnKVfF+U94GjEPL3DKnsZVDkEN8bRAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJAeQUyhptoT02QaFRKuRKwZy3IIFitGfY7PfL8O0/Rbvq3lphIKklcQy6+UIHYYaO4+Z2wDivnXr0eZKYCHF7d4qWbFtvdnbPCILraZLqz8ggjJbJX3QCiUFb1G/K1U9YS7fmS8Ny5FN67hjty9KsuJRBKuqOOZi7hGi8DlNSysWRTNH6jdaBJgtp+DQyEeEFDOXDd4JJY7R/0p1McqHwD/zw3MHRAyFVx2BPB7+onXCSMclcjEvrn7uLPqUHIXzTkI0/WulwzuhqGv6wVgHeW36a33hDddqRH9c14tpsejmg0JvsGBynuHGDjQ665QHMaMNzaOMJzoi0iSejPSG2w=";


    @Test
    public void testBrokerNominalCaseWithSaml2() throws Exception {
        String contextUuid = UUID.randomUUID().toString();
        StringBuffer requestBuffer = new StringBuffer();

        WsFedClient client = new WsFedClientBuilder()
                .authRequest(new URI(WSFED_LOGIN_URL), DUMMY_IDP_URL, CLIENT_ID, contextUuid).build()
                .login().idp("wsfed").build()
                .execute(resp -> {
                    try {
                        requestBuffer.append(EntityUtils.toString(resp.getEntity()));
                    } catch (IOException ex) {
                        fail(ex.getMessage());
                    }
                });

        String request = requestBuffer.toString();
        String extContextId = checkAutoPostFormContentForRequest(request);

        // generate the token
        X509Certificate certificate = TestCryptoUtil.parseCertificate(IDP_CERTIFICATE);
        PrivateKey privateKey = TestCryptoUtil.parsePrivateKey(IDP_PRIVATE_KEY);
        String wsFedToken = createWsFedResponseTokenWithSaml2(extContextId, certificate, privateKey);

        // execute the response (post WS-Fed content), use former http client context to re-use the cookies
        String responseEntity = new WsFedClientBuilder()
                .authResponse(new URI(WSFED_BROKER_LOGIN_URL), wsFedToken, WSFED_BROKER_CLIENT_ID, extContextId, client.getContext()).build()
                .executeAndTransform(resp -> {
                    assertThat(resp.getStatusLine().getStatusCode(), equalTo(200));
                    return EntityUtils.toString(resp.getEntity());
                });

        // ensure that login succeeded, and that we landed on the "update account information" page
        assertThat(responseEntity, containsString("Update Account Information"));
    }

    @Test
    public void testBrokerNominalCaseWithSaml11() throws Exception {
        String contextUuid = UUID.randomUUID().toString();
        StringBuffer requestBuffer = new StringBuffer();

        WsFedClient client = new WsFedClientBuilder()
                .authRequest(new URI(WSFED_LOGIN_URL), DUMMY_IDP_URL, CLIENT_ID, contextUuid).build()
                .login().idp("wsfed").build()
                .execute(resp -> {
                    try {
                        requestBuffer.append(EntityUtils.toString(resp.getEntity()));
                    } catch (IOException ex) {
                        fail(ex.getMessage());
                    }
                });

        String request = requestBuffer.toString();
        String extContextId = checkAutoPostFormContentForRequest(request);

        // generate the token
        X509Certificate certificate = TestCryptoUtil.parseCertificate(IDP_CERTIFICATE);
        PrivateKey privateKey = TestCryptoUtil.parsePrivateKey(IDP_PRIVATE_KEY);
        String wsFedToken = createWsFedResponseTokenWithSaml11(extContextId, certificate, privateKey);

        // execute the response (post WS-Fed content), use former http client context to re-use the cookies
        String responseEntity = new WsFedClientBuilder()
                .authResponse(new URI(WSFED_BROKER_LOGIN_URL), wsFedToken, WSFED_BROKER_CLIENT_ID, extContextId, client.getContext()).build()
                .executeAndTransform(resp -> {
                    assertThat(resp.getStatusLine().getStatusCode(), equalTo(200));
                    return EntityUtils.toString(resp.getEntity());
                });

        // ensure that login succeeded, and that we landed on the "update account information" page
        assertThat(responseEntity, containsString("Update Account Information"));
    }

    @Test
    public void testBrokerCaseWithSaml2SignedByWrongKey() throws Exception {
        String contextUuid = UUID.randomUUID().toString();
        StringBuffer requestBuffer = new StringBuffer();

        WsFedClient client = new WsFedClientBuilder()
                .authRequest(new URI(WSFED_LOGIN_URL), DUMMY_IDP_URL, CLIENT_ID, contextUuid).build()
                .login().idp("wsfed").build()
                .execute(resp -> {
                    try {
                        requestBuffer.append(EntityUtils.toString(resp.getEntity()));
                    } catch (IOException ex) {
                        fail(ex.getMessage());
                    }
                });

        String request = requestBuffer.toString();
        String extContextId = checkAutoPostFormContentForRequest(request);

        // generate the token
        X509Certificate certificate = TestCryptoUtil.parseCertificate(IDP_WRONG_CERTIFICATE);
        PrivateKey privateKey = TestCryptoUtil.parsePrivateKey(IDP_WRONG_PRIVATE_KEY);
        String wsFedToken = createWsFedResponseTokenWithSaml2(extContextId, certificate, privateKey);

        // execute the response (post WS-Fed content), use former http client context to re-use the cookies
        String responseEntity = new WsFedClientBuilder()
                .authResponse(new URI(WSFED_BROKER_LOGIN_URL), wsFedToken, WSFED_BROKER_CLIENT_ID, extContextId, client.getContext()).build()
                .executeAndTransform(resp -> {
                    assertThat(resp.getStatusLine().getStatusCode(), equalTo(400));
                    return EntityUtils.toString(resp.getEntity());
                });

        // ensure that login succeeded, and that we landed on the "update account information" page
        assertThat(responseEntity, containsString("invalidFederatedIdentityActionMessage"));
    }

    @Test
    public void testBrokerCaseWithSaml11SignedByWrongKey() throws Exception {
        String contextUuid = UUID.randomUUID().toString();
        StringBuffer requestBuffer = new StringBuffer();

        WsFedClient client = new WsFedClientBuilder()
                .authRequest(new URI(WSFED_LOGIN_URL), DUMMY_IDP_URL, CLIENT_ID, contextUuid).build()
                .login().idp("wsfed").build()
                .execute(resp -> {
                    try {
                        requestBuffer.append(EntityUtils.toString(resp.getEntity()));
                    } catch (IOException ex) {
                        fail(ex.getMessage());
                    }
                });

        String request = requestBuffer.toString();
        String extContextId = checkAutoPostFormContentForRequest(request);

        // generate the token
        X509Certificate certificate = TestCryptoUtil.parseCertificate(IDP_WRONG_CERTIFICATE);
        PrivateKey privateKey = TestCryptoUtil.parsePrivateKey(IDP_WRONG_PRIVATE_KEY);
        String wsFedToken = createWsFedResponseTokenWithSaml11(extContextId, certificate, privateKey);

        // execute the response (post WS-Fed content), use former http client context to re-use the cookies
        String responseEntity = new WsFedClientBuilder()
                .authResponse(new URI(WSFED_BROKER_LOGIN_URL), wsFedToken, WSFED_BROKER_CLIENT_ID, extContextId, client.getContext()).build()
                .executeAndTransform(resp -> {
                    assertThat(resp.getStatusLine().getStatusCode(), equalTo(400));
                    return EntityUtils.toString(resp.getEntity());
                });

        // ensure that login succeeded, and that we landed on the "update account information" page
        assertThat(responseEntity, containsString("invalidFederatedIdentityActionMessage"));
    }

    /**
     * Check the content of the auto-post form, and return the context (wctx) information
     */
    private String checkAutoPostFormContentForRequest(String request) {
        Document doc = Jsoup.parse(request);
        // check autopost of the form
        assertThat(doc.body().attr("Onload"), containsString("document.forms[0].submit()"));
        // check form content
        Element form = doc.selectFirst("form");
        assertThat(form, not(nullValue()));
        assertThat(form.attr("ACTION"), equalTo(DUMMY_IDP_URL));
        assertThat(form.childNodeSize(), equalTo(5));

        String wctx = null;
        for (Node input : form.childNodes()) {
            if ("noscript".equalsIgnoreCase(input.nodeName())) {
                // check that there is a button for manual posting of the form
                for (Node elements : input.childNodes()) {
                    if ("p".equalsIgnoreCase(elements.nodeName())) {
                        // skip, nothing to check in the message
                    } else if ("input".equalsIgnoreCase(elements.nodeName())) {
                        assertThat(elements.attr("type"), equalToIgnoringCase("submit"));
                    } else {
                        fail("Unexpected field in form");
                    }
                }
            } else {
                switch (input.attr("name")) {
                    case "wa":
                        assertThat(input.attr("value"), equalTo(WSFedConstants.WSFED_SIGNIN_ACTION));
                        break;
                    case "wctx":
                        wctx = input.attr("value");
                        assertThat(wctx, not(nullValue()));
                        break;
                    case "wtrealm":
                        assertThat(input.attr("value"), equalTo(DUMMY_IDP_CLIENT_ID));
                        break;
                    case "wreply":
                        assertThat(input.attr("value"), equalTo(WSFED_BROKER_LOGIN_URL));
                        break;
                    default:
                        fail("Unexpected field in form");
                }
            }
        }
        return wctx;
    }

    /**
     * create a WS-Fed token with a SAML 2.0 assertion
     */
    private String createWsFedResponseTokenWithSaml2(String contextId, X509Certificate certificate, PrivateKey privateKey) throws Exception {
        RequestSecurityTokenResponseBuilder builder = new RequestSecurityTokenResponseBuilder();

        builder.setRealm("clientId")
                .setContext(contextId)
                .setAction(WSFedConstants.WSFED_SIGNIN_ACTION)
                .setDestination(WSFED_BROKER_LOGIN_URL)
                .setTokenExpiration(60)
                .setRequestIssuer(DUMMY_IDP_CLIENT_ID)
                .setSigningKeyPair(new KeyPair(certificate.getPublicKey(), privateKey))
                .setSigningCertificate(certificate);

        // create a SAML2 assertion
        SAML2AssertionTypeBuilder saml2Builder = new SAML2AssertionTypeBuilder();
        saml2Builder.issuer(DUMMY_IDP_ISSUER)
                .requestIssuer(DUMMY_IDP_CLIENT_ID)
                .assertionExpiration(60)
                .subjectExpiration(60)
                .nameIdentifier(JBossSAMLURIConstants.NAMEID_FORMAT_UNSPECIFIED.get(), "bburke");
        AssertionType assertion = saml2Builder.buildModel();

        return builder.setSamlToken(assertion).getStringValue();
    }

    /**
     * create a WS-Fed token with a SAML 1.1 assertion
     */
    private String createWsFedResponseTokenWithSaml11(String contextId, X509Certificate certificate, PrivateKey privateKey) throws Exception {
        RequestSecurityTokenResponseBuilder builder = new RequestSecurityTokenResponseBuilder();

        builder.setRealm("clientId")
                .setContext(contextId)
                .setAction(WSFedConstants.WSFED_SIGNIN_ACTION)
                .setDestination(WSFED_BROKER_LOGIN_URL)
                .setTokenExpiration(60)
                .setRequestIssuer(DUMMY_IDP_CLIENT_ID)
                .setSigningKeyPair(new KeyPair(certificate.getPublicKey(), privateKey))
                .setSigningCertificate(certificate);

        // create a SAML2 assertion
        SAML11AssertionTypeBuilder saml11Builder = new SAML11AssertionTypeBuilder();
        saml11Builder.issuer(DUMMY_IDP_ISSUER)
                .assertionExpiration(60)
                .nameIdentifier(JBossSAMLURIConstants.NAMEID_FORMAT_UNSPECIFIED.get(), "bburke")
                .requestIssuer(DUMMY_IDP_CLIENT_ID);
        SAML11AssertionType assertion = saml11Builder.buildModel();

        return builder.setSaml11Token(assertion).getStringValue();
    }

}
