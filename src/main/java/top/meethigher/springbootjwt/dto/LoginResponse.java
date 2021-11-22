package top.meethigher.springbootjwt.dto;

import io.swagger.annotations.ApiModel;
import top.meethigher.springbootjwt.entity.User;

/**
 * LoginResponse
 *
 * @author chenchuancheng
 * @github https://github.com/meethigher
 * @blog https://meethigher.top
 * @time 2021/11/14 16:13
 */
@ApiModel(value="LoginResponse",description = "登录返回结果")
public class LoginResponse {
    private String desc;
    private User user;
    private String token;

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getDesc() {
        return desc;
    }

    public void setDesc(String desc) {
        this.desc = desc;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }
}
