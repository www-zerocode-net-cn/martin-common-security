package com.java2e.martin.common.security;

import cn.hutool.core.convert.Convert;
import com.java2e.martin.common.security.config.HttpSecurityDealer;
import com.java2e.martin.common.security.properties.PermitAllUrlProperties;
import com.java2e.martin.common.security.properties.RemoteTokenServiceProperties;
import com.java2e.martin.common.security.component.ResourceAuthExceptionEntryPoint;
import com.java2e.martin.common.security.dynamic.DynamicAccessDecisionManager;
import com.java2e.martin.common.security.dynamic.DynamicSecurityFilter;
import com.java2e.martin.common.security.dynamic.DynamicSecurityMetadataSource;
import com.java2e.martin.common.security.dynamic.RestAuthenticationEntryPoint;
import com.java2e.martin.common.security.dynamic.RestfulAccessDeniedHandler;
import com.java2e.martin.common.security.handler.RestResponseErrorHandler;
import com.java2e.martin.common.security.interceptor.FeignInnerInterceptor;
import com.java2e.martin.common.security.interceptor.MartinOAuth2FeignRequestInterceptor;
import com.java2e.martin.common.security.provider.token.MartinUserAuthenticationConverter;
import feign.RequestInterceptor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.oauth2.OAuth2ClientProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.OkHttp3ClientHttpRequestFactory;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;
import org.springframework.security.oauth2.provider.token.UserAuthenticationConverter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.ArrayList;
import java.util.Map;

/**
 * @author 狮少
 * @version 1.0
 * @date 2019/5/29
 * @describtion 自动配置Martin安全服务
 * @since 1.0
 */
@Slf4j
@Configuration
@EnableCaching
@EnableConfigurationProperties({PermitAllUrlProperties.class,RemoteTokenServiceProperties.class})
@ConditionalOnProperty(
        prefix = "martin.resource-server",
        name = {"enabled"},
        havingValue = "true",
        matchIfMissing = true
)
@EnableResourceServer
@ComponentScan(basePackages = {"com.java2e.martin.common.security", "com.java2e.martin.common.core"})
public class MartinSecurityAutoConfiguration extends ResourceServerConfigurerAdapter implements WebMvcConfigurer, ApplicationContextAware {

    @Autowired
    private RemoteTokenServiceProperties remoteTokenServiceProperties;
    @Autowired
    private ResourceAuthExceptionEntryPoint resourceAuthExceptionEntryPoint;
    @Autowired
    private FeignInnerInterceptor feignInnerInterceptor;
    private ApplicationContext applicationContext;

    @Autowired
    private HttpSecurityDealer httpSecurityDealer;

    @Autowired
    private PermitAllUrlProperties permitAllUrlProperties;

    /**
     * 默认的配置，对外暴露
     *
     * @param httpSecurity
     */
    @Override
    @SneakyThrows
    public void configure(HttpSecurity httpSecurity) {
        ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry registry =
                httpSecurityDealer.martinExpressionInterceptUrlRegistry(httpSecurity,permitAllUrlProperties.getIgnoreUrls());

        //有动态权限配置时添加动态权限校验过滤器
        registry.and().addFilterAfter(dynamicSecurityFilter(), FilterSecurityInterceptor.class);
        // 任何请求需要身份认证
        registry.and()
                .authorizeRequests()
                .anyRequest()
                .authenticated()
                // 关闭跨站请求防护及不使用session
                .and()
                .csrf()
                .disable()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                // 自定义权限拒绝处理类
                .and()
                .exceptionHandling()
                .accessDeniedHandler(restfulAccessDeniedHandler())
                .authenticationEntryPoint(restAuthenticationEntryPoint());
    }



    @Bean
    public RestfulAccessDeniedHandler restfulAccessDeniedHandler() {
        return new RestfulAccessDeniedHandler();
    }

    @Bean
    public RestAuthenticationEntryPoint restAuthenticationEntryPoint() {
        return new RestAuthenticationEntryPoint();
    }

    @Bean
    public DynamicAccessDecisionManager dynamicAccessDecisionManager() {
        return new DynamicAccessDecisionManager();
    }

    @Bean
    public DynamicSecurityFilter dynamicSecurityFilter() {
        return new DynamicSecurityFilter();
    }

    @Bean
    public DynamicSecurityMetadataSource dynamicSecurityMetadataSource() {
        return new DynamicSecurityMetadataSource();
    }

    /**
     * 将RemoteTokenServices暴露为bean，供给下游服务自动校验权限
     *
     * @return
     */
    @Bean
    public RemoteTokenServices remoteTokenServices() {
        RemoteTokenServices remoteTokenServices = new RemoteTokenServices();
        OAuth2ClientProperties oAuth2ClientProperties = remoteTokenServiceProperties.getOAuth2ClientProperties();
        log.debug("oAuth2ClientProperties==============={}", Convert.toStr(oAuth2ClientProperties));
        ResourceServerProperties resourceServerProperties = remoteTokenServiceProperties.getResourceServerProperties();
        log.debug("resourceServerProperties==============={}", Convert.toStr(resourceServerProperties));
        remoteTokenServices.setCheckTokenEndpointUrl(resourceServerProperties.getTokenInfoUri());
        remoteTokenServices.setClientId(oAuth2ClientProperties.getClientId());
        remoteTokenServices.setClientSecret(oAuth2ClientProperties.getClientSecret());
        DefaultAccessTokenConverter accessTokenConverter = new DefaultAccessTokenConverter();
        UserAuthenticationConverter userTokenConverter = new MartinUserAuthenticationConverter();
        accessTokenConverter.setUserTokenConverter(userTokenConverter);
        remoteTokenServices.setAccessTokenConverter(accessTokenConverter);
        remoteTokenServices.setRestTemplate(OKHttp3RestTemplate());
        return remoteTokenServices;
    }

    /**
     * ResourceServerSecurityConfigurer 可以配置多种 token 校验方式，本例用的url认证，还可以基于 redis 实现,默认不配置的话，是基于内存认证
     * 基于redis实现，需要在本模块引入redis的jar包感觉太重了，所以采用的url认证
     * url认证必须配置以下几项：   checkTokenEndpointUrl;  clientId; clientSecret;
     * <p>
     * RemoteTokenServices 会加重认证副武器的压力，因为每个请求都会去认证
     * <p>
     * 还有一种jwt认证方式，虽然可以减少开销，但是也会带来安全性问题
     *
     * @param resources
     */
    @Override
    public void configure(ResourceServerSecurityConfigurer resources) {
        resources.tokenServices(remoteTokenServices());
        resources.authenticationEntryPoint(resourceAuthExceptionEntryPoint);
    }

    @Bean
    public RequestInterceptor martinOAuth2FeignRequestInterceptor() {
        return new MartinOAuth2FeignRequestInterceptor();
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        //feignClient 内部服务调用拦截器
        registry.addInterceptor(feignInnerInterceptor);
    }

    @Bean
    public PasswordEncoder encode() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    @Primary
    @LoadBalanced
    public RestTemplate restTemplate() {
        Map<String, ClientHttpRequestInterceptor> beansOfType = applicationContext.getBeansOfType(ClientHttpRequestInterceptor.class);
        RestTemplate restTemplate = new RestTemplate();
        restTemplate.setInterceptors(new ArrayList<>(beansOfType.values()));
        restTemplate.setErrorHandler(new RestResponseErrorHandler());
        return restTemplate;
    }

    @Bean("OKHttp3")
    @Primary
    @LoadBalanced
    public RestTemplate OKHttp3RestTemplate() {
        Map<String, ClientHttpRequestInterceptor> beansOfType = applicationContext.getBeansOfType(ClientHttpRequestInterceptor.class);
        RestTemplate restTemplate = new RestTemplate(new OkHttp3ClientHttpRequestFactory());
        restTemplate.setInterceptors(new ArrayList<>(beansOfType.values()));
        restTemplate.setErrorHandler(new RestResponseErrorHandler());
        return restTemplate;
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }
}
