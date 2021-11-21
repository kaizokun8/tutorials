package com.sharetute.web;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

@RestController
public class ArticlesController {

    @Autowired
    private WebClient webClient;

    @GetMapping(value = {"/", "/articles"})
    public String[] getArticles(@RegisteredOAuth2AuthorizedClient("client-authorization-code")
                                        OAuth2AuthorizedClient authorizedClient) {

        System.out.println("<<OAUTH2>>");
        System.out.println(authorizedClient);
        System.out.println(authorizedClient.getAccessToken().getTokenType());
        System.out.println(authorizedClient.getAccessToken().getTokenValue());
        System.out.println(authorizedClient.getPrincipalName());
        System.out.println(authorizedClient.getAccessToken().getScopes());

        return this.webClient
                .get()
                .uri("http://localhost:8090/articles")
                .attributes(oauth2AuthorizedClient(authorizedClient))
                .retrieve()
                .bodyToMono(String[].class)
                .block();
    }

    @GetMapping(value = {"/token"})
    public String getToken(@RegisteredOAuth2AuthorizedClient("client-authorization-code")
                                   OAuth2AuthorizedClient authorizedClient) {

        return authorizedClient.getAccessToken().getTokenValue();
    }
}