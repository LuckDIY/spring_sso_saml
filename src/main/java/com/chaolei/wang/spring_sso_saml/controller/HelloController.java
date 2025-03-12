package com.chaolei.wang.spring_sso_saml.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {


    @PreAuthorize("hasRole('ROOT_ROLE')")
    @GetMapping("hello")
    public String hello(){
        return "hello";
    }

    @GetMapping("user")
    public Object user(){
        return SecurityContextHolder
                .getContextHolderStrategy().getContext().getAuthentication();
    }
}
