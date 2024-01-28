package com.java2e.martin.common.security.interceptor;

import com.java2e.martin.common.core.constant.SecurityConstants;
import feign.RequestInterceptor;
import feign.RequestTemplate;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;

/**
 * @author 狮少
 * @version 1.0
 * @date 2019/9/2
 * @describtion MartinOAuth2FeignRequestInterceptor
 * @since 1.0
 */
@RefreshScope
@Slf4j
public class MartinOAuth2FeignRequestInterceptor implements RequestInterceptor {
    @Value("${martin.feign.secret:123456}")
    private String secret;

    @Override
    public void apply(RequestTemplate requestTemplate) {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
        HttpServletRequest request = attributes.getRequest();
        //传递 token
        requestTemplate.header("Authorization", request.getHeader("Authorization"));
        log.debug("MartinOAuth2FeignRequestInterceptor,martin-inner secret:{}", secret);
        requestTemplate.header(SecurityConstants.MARTIN_INNER, secret);
    }

}
