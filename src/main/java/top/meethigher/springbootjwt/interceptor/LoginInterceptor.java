package top.meethigher.springbootjwt.interceptor;

import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.util.ObjectUtils;
import org.springframework.web.servlet.HandlerInterceptor;
import top.meethigher.springbootjwt.util.JWTUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.SignatureException;
import java.util.HashMap;

/**
 * LoginInterceptor
 *
 * @author chenchuancheng
 * @github https://github.com/meethigher
 * @blog https://meethigher.top
 * @time 2021/11/14 16:49
 */
public class LoginInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String token = request.getHeader("token");
        HashMap<String, String> map = new HashMap<>();
        try {
            DecodedJWT tokenInfo = JWTUtils.getTokenInfo(token);
        }catch (SignatureVerificationException e) {
            e.printStackTrace();
            map.put("desc","无效签名");
        }catch (TokenExpiredException e) {
            e.printStackTrace();
            map.put("desc","token过期");
        }catch (AlgorithmMismatchException e) {
            e.printStackTrace();
            map.put("desc","token算法不一致");
        }catch (Exception e) {
            e.printStackTrace();
            map.put("desc","无效token");
        }
        //如果没有异常，就放行
        if(!ObjectUtils.isEmpty(map)) {
            //转为json，发回给前端
            String json = new ObjectMapper().writeValueAsString(map);
            response.setContentType("application/json;charset=utf-8");
            response.getWriter().println(json);
            return false;
        }
        return true;
    }
}
