package com.chaolei.wang.spring_sso_saml.security;

import com.alibaba.fastjson.JSONObject;
import com.chaolei.wang.spring_sso_saml.handle.JsonAuthenticationFailureHandler;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpMessageConverterAuthenticationSuccessHandler;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableMethodSecurity
@Configuration
@Slf4j
public class SecurityConfiguration {


    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) ->
                //所有请求，都要认证
                requests.anyRequest().authenticated());
        http.formLogin(new Customizer<FormLoginConfigurer<HttpSecurity>>() {
            @Override
            public void customize(FormLoginConfigurer<HttpSecurity> httpSecurityFormLoginConfigurer) {
                httpSecurityFormLoginConfigurer.loginPage("/login");
                httpSecurityFormLoginConfigurer.usernameParameter("u");
                httpSecurityFormLoginConfigurer.failureHandler(new JsonAuthenticationFailureHandler());
                httpSecurityFormLoginConfigurer.successHandler(new HttpMessageConverterAuthenticationSuccessHandler());
            }
        });
        http.httpBasic(withDefaults());
        http.csrf(new Customizer<CsrfConfigurer<HttpSecurity>>() {
            @Override
            public void customize(CsrfConfigurer<HttpSecurity> httpSecurityCsrfConfigurer) {
                httpSecurityCsrfConfigurer.disable();
            }
        });
        http.exceptionHandling(new Customizer<ExceptionHandlingConfigurer<HttpSecurity>>() {
            @Override
            public void customize(ExceptionHandlingConfigurer<HttpSecurity> httpSecurityExceptionHandlingConfigurer) {
                httpSecurityExceptionHandlingConfigurer.accessDeniedHandler(
                        (request, response,
                         accessDeniedException) -> {

                            response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);

                            PrintWriter writer = response.getWriter();

                            JSONObject resultObject = new JSONObject();
                            resultObject.put("code",401);
                            resultObject.put("msg","你无权访问");

                            writer.write(resultObject.toJSONString());
                            writer.flush();
                            writer.close();
                });
                httpSecurityExceptionHandlingConfigurer.authenticationEntryPoint(new AuthenticationEntryPoint() {
                    @Override
                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                        response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);

                        PrintWriter writer = response.getWriter();

                        JSONObject resultObject = new JSONObject();
                        resultObject.put("code",401);
                        resultObject.put("msg",authException.getMessage());

                        writer.write(resultObject.toJSONString());
                        writer.flush();
                        writer.close();
                    }
                });
            }
        });
        return http.build();
    }


    @Bean
    public InMemoryUserDetailsManager inMemoryUserDetailsManager(SecurityProperties properties,
                                                                 ObjectProvider<PasswordEncoder> passwordEncoder) {
        /*SecurityProperties.User user = properties.getUser();
        List<String> roles = user.getRoles();
        return new InMemoryUserDetailsManager(User.withUsername(user.getName())
                .password(getOrDeducePassword(user, passwordEncoder.getIfAvailable()))
                .roles(StringUtils.toStringArray(roles))
                .build());*/

        // DaoAuthenticationProvider 默认已经提供了丰富的加密算法，这里不再重复实现
        return new InMemoryUserDetailsManager(User.withUsername("user")
                .password("{noop}123456")
                .roles("USER_ROLE")
                .build(), User.withUsername("root")
                .password("{bcrypt}$2a$10$JbKvNC1Io6avRczv.a7Wf.3r38Q1P7RsaTZ2sYmaz6d5Y4ImTdAUC")
                .roles("ROOT_ROLE")
                .build());
    }

    public static void main(String[] args) {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        String encode = bCryptPasswordEncoder.encode("123456");
        System.out.println(encode);
    }
}
