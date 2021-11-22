package top.meethigher.springbootjwt.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

/**
 * JWTUtils
 *
 * @author chenchuancheng
 * @github https://github.com/meethigher
 * @blog https://meethigher.top
 * @time 2021/11/14 16:27
 */
public class JWTUtils {
    private static String SECRET = "meethigher";


    /**
     * 生成payload
     * 注意：payload里面不存放敏感信息
     * @param id
     * @param name
     * @return
     */
    public static Map<String,String> generatePayload(String id,String name) {
        HashMap<String, String> payload = new HashMap<>();
        payload.put("id",id);
        payload.put("name",name);
        return payload;
    }
    /**
     * 传入Payload生成jwt
     *
     * @param payload
     * @return
     */
    public static String getToken(Map<String, String> payload) {
        Calendar calendar = Calendar.getInstance();
        //7天过期
        calendar.add(Calendar.DAY_OF_MONTH, 7);

        //第一种存payload方式：遍历map存入
//        JWTCreator.Builder builder = JWT.create();
//        map.forEach(builder::withClaim);
        //第二种存payload方式：直接放map,底层采用的也是第一种方式
        return JWT.create()
                .withPayload(payload)
                .withExpiresAt(calendar.getTime())
                .sign(Algorithm.HMAC256(SECRET));

    }

    /**
     * 校验签名是否正确，并返回token信息
     *
     * @param token
     * @return
     */
    public static DecodedJWT getTokenInfo(String token) {
        return JWT.require(Algorithm.HMAC256(SECRET))
                .build()
                .verify(token);
    }
}
