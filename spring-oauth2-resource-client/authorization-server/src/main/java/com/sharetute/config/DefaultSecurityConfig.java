package com.sharetute.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebSecurity
public class DefaultSecurityConfig {

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

        http.authorizeRequests(authorizeRequests ->
                        authorizeRequests.antMatchers("/h2/**").permitAll()
                                .anyRequest().authenticated())
                .formLogin(withDefaults())
                .csrf().disable()
                .headers().frameOptions().disable();

        return http.build();
    }
/*
    // @formatter:off
    @Bean
    UserDetailsService users() {
        UserDetails user = User.builder()
                .username("user")
                .password("$2a$10$uOmmclnyUaQqv4ZfDMHcluhbF9ffK1IKjhXhJAXz0vD/Fus.AHYDO")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }
    // @formatter:on
*/
    @Bean
    UserDetailsService users(DataSource dataSource, PasswordEncoder passwordEncoder) {

        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);

        UserDetails userDetails = new User("john",
                passwordEncoder.encode("password"),
                List.of(new SimpleGrantedAuthority("ROLE_USER")));

        jdbcUserDetailsManager.createUser(userDetails);

        return jdbcUserDetailsManager;
    }

}
