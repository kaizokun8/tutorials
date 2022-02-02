package com.sharetute.web;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ArticlesController {

    @GetMapping("/articles")
    public String[] getArticles(@AuthenticationPrincipal Jwt principal) {

        System.out.println(principal.getTokenValue());
        principal.getClaims().forEach((k, v) -> System.out.println(k + " " + v));

        return new String[]{"Article 1", "Article 2", "Article 3"};
    }
}