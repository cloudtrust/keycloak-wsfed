package com.quest.keycloak.integration.steps;

import com.quest.keycloak.common.wsfed.WSFedConstants;
import com.quest.keycloak.integration.WsFedClientBuilder;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicNameValuePair;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/** Inspired from the parent project https://github.com/keycloak/keycloak */
public class CreateWsFedAuthResponseStepBuilder extends AbstractStepBuilder {

    private final URI authServerWsFedUrl;
    private final String wsFedToken;
    private final String clientId;
    private final String context;
    private final HttpClientContext originalHttpRequestContext;

    public CreateWsFedAuthResponseStepBuilder(WsFedClientBuilder clientBuilder, URI authServerWsFedUrl, String wsFedToken, String clientId, String context, HttpClientContext httpClientContext) {
        super(clientBuilder);
        this.authServerWsFedUrl = authServerWsFedUrl;
        this.wsFedToken = wsFedToken;
        this.clientId = clientId;
        this.context = context;
        this.originalHttpRequestContext = httpClientContext;
    }


    @Override
    public HttpUriRequest perform(CloseableHttpClient client, URI currentURI, CloseableHttpResponse currentResponse, HttpClientContext httpClientContext) throws Exception {
        List<NameValuePair> formParams = new ArrayList<NameValuePair>();
        formParams.add(new BasicNameValuePair("wa", WSFedConstants.WSFED_SIGNIN_ACTION));
        formParams.add(new BasicNameValuePair("wtrealm", clientId));
        formParams.add(new BasicNameValuePair("wresult", wsFedToken));
        formParams.add(new BasicNameValuePair("wctx", context));

        HttpPost post = new HttpPost(authServerWsFedUrl);
        UrlEncodedFormEntity formEntity = new UrlEncodedFormEntity(formParams, "UTF-8");
        post.setEntity(formEntity);

        httpClientContext.setCookieStore(originalHttpRequestContext.getCookieStore());

        return post;
    }

}
