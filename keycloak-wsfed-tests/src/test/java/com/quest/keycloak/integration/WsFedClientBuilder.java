package com.quest.keycloak.integration;

import com.quest.keycloak.integration.builder.LoginBuilder;
import com.quest.keycloak.integration.steps.CreateWsFedAuthRequestStepBuilder;
import com.quest.keycloak.integration.steps.CreateWsFedAuthResponseStepBuilder;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.protocol.HttpClientContext;
import org.hamcrest.Matcher;
import org.junit.Assert;

import java.net.URI;
import java.util.LinkedList;
import java.util.List;
import java.util.function.Consumer;

import static org.hamcrest.Matchers.notNullValue;

/** Inspired from the parent project https://github.com/keycloak/keycloak */
public class WsFedClientBuilder {

    private final List<WsFedClient.Step> steps = new LinkedList<>();

    /**
     * Execute the current steps without any work on the final response.
     *
     * @return Client that executed the steps
     */
    public WsFedClient execute() {
        return execute(resp -> {
        });
    }

    /**
     * Execute the current steps and pass the final response to the {@code resultConsumer} for processing.
     *
     * @param resultConsumer This function is given the final response
     * @return Client that executed the steps
     */
    public WsFedClient execute(Consumer<CloseableHttpResponse> resultConsumer) {
        final WsFedClient wsFedClient = new WsFedClient();
        wsFedClient.executeAndTransform(r -> {
            resultConsumer.accept(r);
            return null;
        }, steps);
        return wsFedClient;
    }

    /**
     * Execute the current steps and pass the final response to the {@code resultTransformer} for processing.
     *
     * @param resultTransformer This function is given the final response and processes it into some value
     * @return Value returned by {@code resultTransformer}
     */
    public <T> T executeAndTransform(WsFedClient.ResultExtractor<T> resultTransformer) {
        return new WsFedClient().executeAndTransform(resultTransformer, steps);
    }

    public List<WsFedClient.Step> getSteps() {
        return steps;
    }

    public <T extends WsFedClient.Step> T addStepBuilder(T step) {
        steps.add(step);
        return step;
    }

    /**
     * Adds a single generic step
     *
     * @param step
     * @return This builder
     */
    public WsFedClientBuilder addStep(WsFedClient.Step step) {
        steps.add(step);
        return this;
    }

    /**
     * Adds a single generic step
     *
     * @param stepWithNoParameters
     * @return This builder
     */
    public WsFedClientBuilder addStep(Runnable stepWithNoParameters) {
        addStep((client, currentURI, currentResponse, context) -> {
            stepWithNoParameters.run();
            return null;
        });
        return this;
    }

    public WsFedClientBuilder assertResponse(Matcher<HttpResponse> matcher) {
        steps.add((client, currentURI, currentResponse, context) -> {
            Assert.assertThat(currentResponse, matcher);
            return null;
        });
        return this;
    }

    /**
     * When executing the {@link HttpUriRequest} obtained from the previous step,
     * do not to follow HTTP redirects but pass the first response immediately
     * to the following step.
     *
     * @return This builder
     */
    public WsFedClientBuilder doNotFollowRedirects() {
        this.steps.add(new WsFedClient.DoNotFollowRedirectStep());
        return this;
    }

    public WsFedClientBuilder clearCookies() {
        this.steps.add((client, currentURI, currentResponse, context) -> {
            context.getCookieStore().clear();
            return null;
        });
        return this;
    }

    /**
     * Creates fresh and issues an WsFed redirection to the IDP
     */
    public CreateWsFedAuthRequestStepBuilder authRequest(URI authServerWsFedUrl, String consumerUrl, String clientId, String context) {
        return addStepBuilder(new CreateWsFedAuthRequestStepBuilder(this, authServerWsFedUrl, consumerUrl, clientId, context));
    }

    /**
     * Creates and issues an WsFed response to the given client
     */
    public CreateWsFedAuthResponseStepBuilder authResponse(URI authClientWsFedUrl, String wsFedToken, String clientId, String context, HttpClientContext httpClientContext) {
        return addStepBuilder(new CreateWsFedAuthResponseStepBuilder(this, authClientWsFedUrl, wsFedToken, clientId, context, httpClientContext));
    }


    /**
     * Handles login page
     */
    public LoginBuilder login() {
        return addStepBuilder(new LoginBuilder(this));
    }


    public WsFedClientBuilder navigateTo(String httpGetUri) {
        steps.add((client, currentURI, currentResponse, context) -> new HttpGet(httpGetUri));
        return this;
    }

    public WsFedClientBuilder navigateTo(URI httpGetUri) {
        steps.add((client, currentURI, currentResponse, context) -> new HttpGet(httpGetUri));
        return this;
    }

    public WsFedClientBuilder followOneRedirect() {
        return
                doNotFollowRedirects()
                        .addStep((client, currentURI, currentResponse, context) -> {
                            //Assert.assertThat(currentResponse, Matchers.statusCodeIsHC(Status.FOUND));
                            Assert.assertThat("Location header not found", currentResponse.getFirstHeader("Location"), notNullValue());
                            return new HttpGet(currentResponse.getFirstHeader("Location").getValue());
                        });
    }

}
