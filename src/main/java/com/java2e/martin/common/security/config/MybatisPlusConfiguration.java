package com.java2e.martin.common.security.config;

import com.baomidou.mybatisplus.core.handlers.MetaObjectHandler;
import com.baomidou.mybatisplus.extension.plugins.PaginationInterceptor;
import com.java2e.martin.common.core.constant.CommonConstants;
import com.java2e.martin.common.security.util.SecurityContextUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.ibatis.reflection.MetaObject;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.LocalDateTime;

/**
 * @author 狮少
 * @version 1.0
 * @date 2019/11/1
 * @describtion MybatisPlusConfiguration
 * @since 1.0
 */
@Configuration
@Slf4j
public class MybatisPlusConfiguration implements MetaObjectHandler {
    /**
     * 分页插件
     */
    @Bean
    public PaginationInterceptor paginationInterceptor() {
        return new PaginationInterceptor();
    }

    /**
     * 在进行填充时，需要保证填充对象与填充数据类型一致，不然无法填充
     *
     * @param metaObject
     */
    @Override
    public void insertFill(MetaObject metaObject) {
        log.info("start insert fill ....");
        if (SecurityContextUtil.getUser() != null) {
            this.setInsertFieldValByName(CommonConstants.CREATOR, SecurityContextUtil.getUser().getUsername() + "", metaObject);
        }
        this.setInsertFieldValByName(CommonConstants.CREATE_TIME, LocalDateTime.now(), metaObject);
    }

    @Override
    public void updateFill(MetaObject metaObject) {
        log.info("start update fill ....");
        if (SecurityContextUtil.getUser() != null) {
            this.setUpdateFieldValByName(CommonConstants.UPDATER, SecurityContextUtil.getUser().getUsername() + "", metaObject);
        }
        this.setUpdateFieldValByName(CommonConstants.UPDATE_TIME, LocalDateTime.now(), metaObject);
    }
}
