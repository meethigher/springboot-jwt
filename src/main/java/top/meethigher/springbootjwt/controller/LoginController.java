package top.meethigher.springbootjwt.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import top.meethigher.springbootjwt.dto.EditUser;
import top.meethigher.springbootjwt.dto.LoginResponse;
import top.meethigher.springbootjwt.entity.User;
import top.meethigher.springbootjwt.service.LoginService;

import java.util.List;

/**
 * LoginController
 *
 * @author chenchuancheng
 * @github https://github.com/meethigher
 * @blog https://meethigher.top
 * @time 2021/11/13 15:13
 */
@RestController
@Api(value = "LoginController",tags = "登录模块")
@RequestMapping("/user")
public class LoginController {

    @Autowired
    private LoginService loginService;

    @ApiOperation(value = "创建/修改用户", notes = "创建/修改用户")
    @PostMapping("/editUser")
    public User editUser(@RequestBody @Validated EditUser editUser) throws Exception {
        return loginService.editUser(editUser);
    }

    @ApiOperation("查询所有用户")
    @PostMapping("/findAll")
    public List<User> findAll() {
        return loginService.findAll();
    }

    @ApiOperation("查询当前登录人信息")
    @PostMapping("/getLogInfo")
    public User getLogInfo() {
        return loginService.getLogInfo();
    }

    @ApiOperation(value="登录",notes = "登录")
    @PostMapping("/login")
    public LoginResponse login(@RequestBody @Validated EditUser editUser) {
        return loginService.login(editUser);
    }
}
