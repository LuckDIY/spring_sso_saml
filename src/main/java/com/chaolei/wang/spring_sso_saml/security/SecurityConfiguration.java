package com.chaolei.wang.spring_sso_saml.security;

import com.chaolei.wang.spring_sso_saml.handle.JsonAccessDeniedHandler;
import com.chaolei.wang.spring_sso_saml.handle.JsonAuthenticationEntryPoint;
import com.chaolei.wang.spring_sso_saml.handle.JsonAuthenticationFailureHandler;
import com.chaolei.wang.spring_sso_saml.manager.DiyInMemoryUserDetailsManager;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.saml2.Saml2LoginConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpMessageConverterAuthenticationSuccessHandler;
import org.springframework.util.StringUtils;

import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding.REDIRECT;

@EnableMethodSecurity
@Configuration
@Slf4j
public class SecurityConfiguration {


    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) ->
                //所有请求，都要认证
                requests.anyRequest().authenticated());
        /*http.formLogin(new Customizer<FormLoginConfigurer<HttpSecurity>>() {
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
        });*/
        http.exceptionHandling(new Customizer<ExceptionHandlingConfigurer<HttpSecurity>>() {
            @Override
            public void customize(ExceptionHandlingConfigurer<HttpSecurity> httpSecurityEHC) {
                httpSecurityEHC.accessDeniedHandler(new JsonAccessDeniedHandler());
                //httpSecurityEHC.authenticationEntryPoint(new JsonAuthenticationEntryPoint());
            }
        });

        http.saml2Login(new Customizer<Saml2LoginConfigurer<HttpSecurity>>() {
            @Override
            public void customize(Saml2LoginConfigurer<HttpSecurity> httpSecuritySaml2LoginConfigurer) {
            }
        });

        http.formLogin(form -> form
                .loginPage("/login")  // 配置自定义登录页
                .loginProcessingUrl("/login") // 处理普通表单登录的 URL
                .defaultSuccessUrl("/user", true) // 登录成功后跳转
                .permitAll()
        );

        return http.build();
    }


    @Bean
    public DiyInMemoryUserDetailsManager inMemoryUserDetailsManager(SecurityProperties properties,
                                                                    ObjectProvider<PasswordEncoder> passwordEncoder) {
        /*SecurityProperties.User user = properties.getUser();
        List<String> roles = user.getRoles();
        return new InMemoryUserDetailsManager(User.withUsername(user.getName())
                .password(getOrDeducePassword(user, passwordEncoder.getIfAvailable()))
                .roles(StringUtils.toStringArray(roles))
                .build());*/

        // DaoAuthenticationProvider 默认已经提供了丰富的加密算法，这里不再重复实现
        return new DiyInMemoryUserDetailsManager(User.withUsername("user")
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


    /*@Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
        return new InMemoryRelyingPartyRegistrationRepository(
                RelyingPartyRegistrations
                        //https://dev-60686317.okta.com/app/exkntekpwvR5XckyO5d7/sso/saml/metadata
                        .fromMetadataLocation("https://idp.example.com/realms/demo/protocol/saml/descriptor")
                        .registrationId("saml-idp")  // 自定义 IdP 识别 ID
                        .assertionConsumerServiceLocation("{baseUrl}/login/saml2/sso/{registrationId}")
                        .singleSignOnServiceBinding(REDIRECT) // SAML 认证方式（默认 Redirect）
                        .build()
        );
    }*/

}
