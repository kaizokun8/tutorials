package com.sharetute.web;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

@RestController
public class ArticlesController {

    @Autowired
    private WebClient webClient;

    @GetMapping(value = {"/", "/articles"})
    public String[] getArticles(
            @RegisteredOAuth2AuthorizedClient("client-authorization-code")
                    OAuth2AuthorizedClient authorizedClient
    ) {
        return this.webClient
                .get()
                .uri("http://127.0.0.1:8090/articles")
                .attributes(oauth2AuthorizedClient(authorizedClient))
                .retrieve()
                .bodyToMono(String[].class)
                .block();
    }

    @GetMapping(value = "/token")
    public String getToken(@RegisteredOAuth2AuthorizedClient("client-authorization-code")
                                   OAuth2AuthorizedClient authorizedClient) {

        System.out.println("name : " + authorizedClient.getPrincipalName());
        System.out.println("token type : " + authorizedClient.getAccessToken().getTokenType().getValue());
        System.out.println("token value : " + authorizedClient.getAccessToken().getTokenValue());

        authorizedClient.getAccessToken().getScopes().forEach(scope -> System.out.println("scope : " + scope));

        return authorizedClient.getAccessToken().getTokenValue();
    }
}