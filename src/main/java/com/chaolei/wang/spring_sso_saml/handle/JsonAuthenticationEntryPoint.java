package com.chaolei.wang.spring_sso_saml.handle;

import com.alibaba.fastjson.JSONObject;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
import java.io.PrintWriter;

/**
 * @author chao.lei
 * 未认证 无权限访问处理
 */
public class JsonAuthenticationEntryPoint implements AuthenticationEntryPoint {
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
}
