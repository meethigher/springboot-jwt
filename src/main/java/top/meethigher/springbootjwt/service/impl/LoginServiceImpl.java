package top.meethigher.springbootjwt.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;
import top.meethigher.springbootjwt.dto.EditUser;
import top.meethigher.springbootjwt.dto.LoginResponse;
import top.meethigher.springbootjwt.entity.User;
import top.meethigher.springbootjwt.repository.UserRepository;
import top.meethigher.springbootjwt.service.LoginService;
import top.meethigher.springbootjwt.util.JWTUtils;

import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Predicate;
import javax.persistence.criteria.Root;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * LoginServiceImpl
 *
 * @author chenchuancheng
 * @github https://github.com/meethigher
 * @blog https://meethigher.top
 * @time 2021/11/13 15:24
 */
@Service
public class LoginServiceImpl implements LoginService {
    @Autowired
    private UserRepository userRepository;


    /**
     * 测试是否能成功登录
     * @param name
     * @param password
     * @return
     */
    private User testLogin(String name,String password) throws Exception {
        Specification<User> queryCondition=new Specification<User>() {
            @Override
            public Predicate toPredicate(Root<User> root, CriteriaQuery<?> cq, CriteriaBuilder cb) {
                Predicate verifyName = cb.equal(root.get("name"), name);
                Predicate verifyPassword = cb.equal(root.get("password"), password);
                return cb.and(verifyName,verifyPassword);
            }
        };
        List<User> userList = userRepository.findAll(queryCondition);
        if(ObjectUtils.isEmpty(userList)) {
            throw new Exception("无法登录，校验用户和密码是否匹配");
        }
        return userList.get(0);
    }
    @Override
    public LoginResponse login(EditUser editUser) {
        LoginResponse loginResponse = new LoginResponse();
        try {
            User user = testLogin(editUser.getName(), editUser.getPassword());
            loginResponse.setDesc("success");
            loginResponse.setUser(user);
            //登录成功，生成jwt
            Map<String, String> payload = JWTUtils.generatePayload(user.getId(), user.getName());
            String jwtToken = JWTUtils.getToken(payload);
            loginResponse.setToken(jwtToken);
        } catch (Exception e) {
            loginResponse.setDesc("failure");
        }
        return loginResponse;
    }

    @Override
    public User editUser(EditUser editUser) throws Exception {
        if(ObjectUtils.isEmpty(editUser.getId())) {
            User user = new User();
            user.setName(editUser.getName());
            user.setPassword(editUser.getPassword());
            userRepository.save(user);
            return user;
        }else {
            User user = verifyUser(editUser.getId());
            user.setName(editUser.getName());
            user.setPassword(editUser.getPassword());
            userRepository.save(user);
            return user;
        }
    }

    /**
     * 校验用户是否存在
     * @param userId
     * @return
     */
    private User verifyUser(String userId) throws Exception {
        Optional<User> optional = userRepository.findById(userId);
        if(optional.isPresent()) {
            return optional.get();
        }else {
            throw new Exception("数据不存在");
        }
    }

    @Override
    public List<User> findAll() {
        return userRepository.findAll();
    }

    @Override
    public User getLogInfo() {
        return null;
    }
}
