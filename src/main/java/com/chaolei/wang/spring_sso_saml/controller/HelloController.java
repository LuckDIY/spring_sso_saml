package com.chaolei.wang.spring_sso_saml.controller;

import com.chaolei.wang.spring_sso_saml.manager.DiyInMemoryUserDetailsManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@RestController
public class HelloController {

    /*@Autowired
    private DiyInMemoryUserDetailsManager diyInMemoryUserDetailsManager;*/

    @PreAuthorize("hasRole('ROOT_ROLE')")
    @GetMapping("hello")
    public String hello(){
        return "hello";
    }

    @PostFilter("authentication.name == 'root' || filterObject.getUsername() == authentication.name")
    @GetMapping("users")
    public List<UserDetails> users(){

        //List<UserDetails> users = diyInMemoryUserDetailsManager.getUsers();
        return null;
    }

    @GetMapping("user")
    public Object user(){
        return SecurityContextHolder
                .getContextHolderStrategy().getContext().getAuthentication();
    }
}
