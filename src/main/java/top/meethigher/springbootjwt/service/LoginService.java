package top.meethigher.springbootjwt.service;

import top.meethigher.springbootjwt.dto.EditUser;
import top.meethigher.springbootjwt.dto.LoginResponse;
import top.meethigher.springbootjwt.entity.User;

import java.util.List;

/**
 * LoginService
 *
 * @author chenchuancheng
 * @github https://github.com/meethigher
 * @blog https://meethigher.top
 * @time 2021/11/13 15:22
 */
public interface LoginService {

    /**
     * 登录
     * @param user
     * @return
     */
    LoginResponse login(EditUser user);

    /**
     * 编辑用户
     * @param user
     * @return
     */
    User editUser(EditUser user) throws Exception;

    /**
     * 查询所有
     * @return
     */
    List<User> findAll();

    /**
     * 查询当前登录信息
     * @return
     */
    User getLogInfo();
}
