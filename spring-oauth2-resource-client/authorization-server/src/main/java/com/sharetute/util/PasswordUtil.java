package com.sharetute.util;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class PasswordUtil {

    public static void main(String[] args) {

        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

        String raw = "secret";

        String encoded = passwordEncoder.encode(raw);

        passwordEncoder.matches(raw, encoded);

        System.out.println(encoded);
    }

}
