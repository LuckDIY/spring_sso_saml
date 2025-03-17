package com.chaolei.wang.spring_sso_saml.manager;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.util.*;

public class DiyInMemoryUserDetailsManager extends InMemoryUserDetailsManager {

    private final List<UserDetails> immutableUser;

    public DiyInMemoryUserDetailsManager(UserDetails... users) {
        super(users);
        this.immutableUser = List.of(users);
    }

    public List<UserDetails> getUsers() {
        return immutableUser;
    }

}
