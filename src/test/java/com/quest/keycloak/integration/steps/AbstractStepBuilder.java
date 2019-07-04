package com.quest.keycloak.integration.steps;

import com.quest.keycloak.integration.WsFedClient;
import com.quest.keycloak.integration.WsFedClientBuilder;

/** Inspired from the parent project https://github.com/keycloak/keycloak */
public abstract class AbstractStepBuilder<T extends AbstractStepBuilder<T>> implements WsFedClient.Step {
    private final WsFedClientBuilder clientBuilder;

    public AbstractStepBuilder(WsFedClientBuilder clientBuilder) {
        this.clientBuilder = clientBuilder;
    }

    public WsFedClientBuilder build() {
        return this.clientBuilder;
    }

}
