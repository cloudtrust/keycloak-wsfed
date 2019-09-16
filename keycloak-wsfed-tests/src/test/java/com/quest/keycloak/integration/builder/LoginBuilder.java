package com.quest.keycloak.integration.builder;

import com.quest.keycloak.integration.WsFedClient;
import com.quest.keycloak.integration.WsFedClientBuilder;

import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.hamcrest.Matchers;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Element;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testsuite.admin.Users;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertThat;
import static org.keycloak.testsuite.admin.Users.getPasswordOf;
import static org.keycloak.testsuite.util.Matchers.statusCodeIsHC;

/** Taken from the parent project https://github.com/keycloak/keycloak */
public class LoginBuilder implements WsFedClient.Step {

    private final WsFedClientBuilder clientBuilder;
    private UserRepresentation user;
    private boolean sso = false;
    private String idpAlias;

    public LoginBuilder(WsFedClientBuilder clientBuilder) {
        this.clientBuilder = clientBuilder;
    }

    @Override
    public HttpUriRequest perform(CloseableHttpClient client, URI currentURI, CloseableHttpResponse currentResponse, HttpClientContext context) throws Exception {
        if (sso) {
            return null;    // skip this step
        } else {
            assertThat(currentResponse, statusCodeIsHC(Response.Status.OK));
            String loginPageText = EntityUtils.toString(currentResponse.getEntity(), "UTF-8");
            assertThat(loginPageText, containsString("login"));

            return handleLoginPage(loginPageText, currentURI);
        }
    }

    public WsFedClientBuilder build() {
        return this.clientBuilder;
    }

    public LoginBuilder user(UserRepresentation user) {
        this.user = user;
        return this;
    }

    public LoginBuilder user(String userName, String password) {
        this.user = new UserRepresentation();
        this.user.setUsername(userName);
        Users.setPasswordFor(user, password);
        return this;
    }

    public LoginBuilder sso(boolean sso) {
        this.sso = sso;
        return this;
    }

    /**
     * When the step is executed and {@code idpAlias} is not {@code null}, it attempts to find and follow the link to
     * identity provider with the given alias.
     * @param idpAlias
     * @return
     */
    public LoginBuilder idp(String idpAlias) {
        this.idpAlias = idpAlias;
        return this;
    }

    /**
     * Prepares a GET/POST request for logging the given user into the given login page. The login page is expected
     * to have at least input fields with id "username" and "password".
     *
     * @param loginPage
     * @return
     */
    private HttpUriRequest handleLoginPage(String loginPage, URI currentURI) {
        if (idpAlias != null) {
            org.jsoup.nodes.Document theLoginPage = Jsoup.parse(loginPage);
            Element zocialLink = theLoginPage.getElementById("zocial-" + this.idpAlias);
            assertThat("Unknown idp: " + this.idpAlias, zocialLink, Matchers.notNullValue());
            final String link = zocialLink.attr("href");
            assertThat("Invalid idp link: " + this.idpAlias, link, Matchers.notNullValue());
            return new HttpGet(currentURI.resolve(link));
        }

        return handleLoginPage(user, loginPage);
    }

    public static HttpUriRequest handleLoginPage(UserRepresentation user, String loginPage) {
        String username = user.getUsername();
        String password = getPasswordOf(user);
        org.jsoup.nodes.Document theLoginPage = Jsoup.parse(loginPage);

        List<NameValuePair> parameters = new LinkedList<>();
        for (Element form : theLoginPage.getElementsByTag("form")) {
            String method = form.attr("method");
            String action = form.attr("action");
            boolean isPost = method != null && "post".equalsIgnoreCase(method);

            for (Element input : form.getElementsByTag("input")) {
                if (Objects.equals(input.id(), "username")) {
                    parameters.add(new BasicNameValuePair(input.attr("name"), username));
                } else if (Objects.equals(input.id(), "password")) {
                    parameters.add(new BasicNameValuePair(input.attr("name"), password));
                } else {
                    parameters.add(new BasicNameValuePair(input.attr("name"), input.val()));
                }
            }

            if (isPost) {
                HttpPost res = new HttpPost(action);

                UrlEncodedFormEntity formEntity = new UrlEncodedFormEntity(parameters, StandardCharsets.UTF_8);
                res.setEntity(formEntity);

                return res;
            } else {
                UriBuilder b = UriBuilder.fromPath(action);
                for (NameValuePair parameter : parameters) {
                    b.queryParam(parameter.getName(), parameter.getValue());
                }
                return new HttpGet(b.build());
            }
        }

        throw new IllegalArgumentException("Invalid login form: " + loginPage);
    }

}

