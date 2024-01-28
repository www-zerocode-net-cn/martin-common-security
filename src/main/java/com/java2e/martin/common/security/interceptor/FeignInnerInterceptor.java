package com.java2e.martin.common.security.interceptor;

import cn.hutool.core.collection.CollectionUtil;
import com.java2e.martin.common.core.api.ApiErrorCode;
import com.java2e.martin.common.core.api.R;
import com.java2e.martin.common.core.constant.SecurityConstants;
import com.java2e.martin.common.feign.remote.RemoteUrl;
import com.java2e.martin.common.security.properties.PermitAllUrlProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;
import java.util.Set;

/**
 * @author 狮少
 * @version 1.0
 * @date 2019/9/4
 * @describtion FeignInnerInterceptor, controller前置拦截器，校验内部feign调用秘钥
 * @since 1.0
 */
@Slf4j
@Configuration
@RefreshScope
@EnableConfigurationProperties({PermitAllUrlProperties.class})
public class FeignInnerInterceptor extends HandlerInterceptorAdapter {
    @Value("${martin.feign.secret:123456}")
    private String secret;

    @Autowired
    private PermitAllUrlProperties permitAllUrlProperties;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        List<String> ignoreUrls = permitAllUrlProperties.getIgnoreUrls();
        Set<String> feignUrls = RemoteUrl.REMOTE_URLS;
        //内部feign调用名单为空，则放行
        if (CollectionUtil.isEmpty(feignUrls)) {
            return true;
        }
        String uri = request.getRequestURI();
        //判断是否只允许内部服务调用,定义在feign中的的服务只允许内部调用
        boolean onlyInner = feignUrls.stream().anyMatch(url -> {
            AntPathMatcher matcher = new AntPathMatcher();
            boolean allowOuter = ignoreUrls.stream().anyMatch(u -> {
                log.debug("FeignInnerInterceptor,ignoreUrl: {},uri: {}", u, uri);
                return matcher.match(u, uri);
            });
            log.debug("FeignInnerInterceptor, allowOuter: {}", allowOuter);
            //允许外部访问
            if (allowOuter) {
                return false;
            }
            //是否只允许内部调用
            return matcher.match(url, uri);
        });
        log.debug("FeignInnerInterceptor,onlyInner: {}", onlyInner);
        //不包含在feign内部调用名单，则放行
        if (!onlyInner) {
            return true;
        }
        String martinInner = request.getHeader(SecurityConstants.MARTIN_INNER);
        log.debug("FeignInnerInterceptor,martin-inner secret: {}", martinInner);
        if (null == martinInner || !martinInner.equals(secret)) {
            log.error("FeignInnerInterceptor,{}", R.failed(ApiErrorCode.FORBIDDEN));
            response.sendError(403);
            return false;
        } else {
            return true;
        }
    }

}
