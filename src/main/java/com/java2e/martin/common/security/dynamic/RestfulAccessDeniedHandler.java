package com.java2e.martin.common.security.dynamic;

import cn.hutool.json.JSONUtil;
import com.java2e.martin.common.core.api.ApiErrorCode;
import com.java2e.martin.common.core.api.R;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author 狮少
 * @version 1.0
 * @date 2021/3/24
 * @describtion RestfulAccessDeniedHandler
 * @since 1.0
 */
@Slf4j
public class RestfulAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException e) throws IOException, ServletException {
        log.debug("RestfulAccessDeniedHandler,接口[{}]认证失败：{}", request.getRequestURI(), e);
        response.setHeader("Cache-Control", "no-cache");
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json");
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.getWriter().println(JSONUtil.parse(R.failed(ApiErrorCode.FORBIDDEN)));
        response.getWriter().flush();
    }
}
