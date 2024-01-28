package com.java2e.martin.common.security.userdetail;

import cn.hutool.core.util.StrUtil;
import com.java2e.martin.common.api.system.RemoteSystemUser;
import com.java2e.martin.common.bean.system.User;
import com.java2e.martin.common.bean.system.vo.UserRolePrivilegeVo;
import com.java2e.martin.common.core.api.ApiErrorCode;
import com.java2e.martin.common.core.api.R;
import com.java2e.martin.common.core.constant.CommonConstants;
import com.java2e.martin.common.core.exception.StatefulException;
import com.java2e.martin.common.security.vip.rights.PersonLoginCountRight;
import com.java2e.martin.common.security.vip.rights.PersonRegisterCountRight;
import com.java2e.martin.common.vip.annotation.VIP;
import com.java2e.martin.common.vip.enums.VIPLevelEnum;
import com.java2e.martin.common.vip.enums.VIPModuleEnum;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.Set;

/**
 * @author 狮少
 * @version 1.0
 * @date 2019/9/2
 * @describtion MartinUserDetailsService
 * @since 1.0
 */
@Slf4j
@Service
public class MartinUserDetailsService implements UserDetailsService {
    @Autowired
    private RemoteSystemUser remoteSystem;

    /**
     * 获取用户、权限、菜单
     *
     * @param username
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    @SneakyThrows
    @VIP(module = VIPModuleEnum.ERD, vipLevel = {VIPLevelEnum.NONE, VIPLevelEnum.PRO}, rights = {PersonLoginCountRight.class}, reset = false)
    public MartinUser loadUserByUsername(String username) throws UsernameNotFoundException {
        R<UserRolePrivilegeVo> r = remoteSystem.loadUserByUsername(username);
        return getUserDetails(r);
    }

    private MartinUser getUserDetails(R<UserRolePrivilegeVo> r) {
        if (r.getCode() != ApiErrorCode.OK.getCode()) {
            log.error(r.getMsg());
            throw new StatefulException(ApiErrorCode.fromCode(r.getCode()));
        }
        UserRolePrivilegeVo userRolePrivilegeVo = r.getData();
        log.debug("loadUserByUsername :{},{}", r.getCode(), r.getMsg());
        if (null == userRolePrivilegeVo) {
            log.error("{}", ApiErrorCode.USER_NOT_FOUND);
            throw new StatefulException(ApiErrorCode.USER_NOT_FOUND);
        }
        User sysUser = userRolePrivilegeVo.getUser();

        Set<String> authoritySet = userRolePrivilegeVo.getAuthoritySet();
        log.debug("authoritySet : {}", authoritySet);
        Collection<? extends GrantedAuthority> authorities = AuthorityUtils.createAuthorityList(authoritySet.toArray(new String[0]));

        boolean enabled = StrUtil.equals(sysUser.getDelFlag(), CommonConstants.STATUS_NORMAL);
        boolean accountNonLocked = !StrUtil.equals(sysUser.getLockFlag(), CommonConstants.STATUS_LOCK);
        log.debug("accountNonLocked:{}", accountNonLocked);
        MartinUser martinUser = new MartinUser(sysUser.getId(), sysUser.getDeptId(), userRolePrivilegeVo.getRoles(), sysUser.getTenantId(), sysUser.getUsername(), sysUser.getPwd(), enabled, true, true, accountNonLocked, authorities);
        return martinUser;
    }
}
