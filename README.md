[JWT实现认证](https://meethigher.top/blog/2021/jwt/)

最近一直想写一个类似于待办的东西，由于不想用传统的session，就卡住了，后来在各种群里扯皮，发现除了用缓存之外，还可以通过 JWT 来实现。

参考

* [JSON Web Token Introduction - jwt.io](https://jwt.io/introduction)
* [Spring Data JPA(二)：SpringBoot集成H2_郑龙飞-CSDN博客](https://blog.csdn.net/dandandeshangni/article/details/79668641)

# 一、了解JWT

**概念**

json web token 用于在各方之间以 json 对象安全地传输信息，比如在前端和后端进行传输，或者在A系统与B系统之间进行传输。因为它是用的数字签名，所以此信息能够进行验证的，验证的成功与否决定是否信任。

**作用**

1. 授权：这是jwt应用最广泛的。一旦用户登录，每个后续请求都要包含jwt，从而验证用户是否有权限访问资源。单点登录是jwt应用最广泛的一个代表功能。
2. 信息交换：在前后端之间、系统之间，对jwt进行签名，比如使用非对称加密算法（含有公钥和私钥的方式），可以保证信息被指定的人给获取到。

## **1.1 为什么授权要使用jwt**

比较传统session认证与jwt认证的区别

基于传统的session认证

1. 认证方式：http本身是一种是一种无状态的协议。这就意味着，每次进行请求，都要带着用户名和密码来进行用户认证。为了解决这个问题，我们需要在服务端存储一份用户登录的信息，这个登录信息会在响应时传递给客户端，保存成cookie，以便下次携带发送给服务端。这份服务端存储的登录信息就是session。
2. 缺点
   * 每个用户进行认证之后，服务器都要在服务端做一次记录，以便鉴别下次用户请求时的身份。通常而言，session都是保存在内存中，而随着认证用户的增多，服务端的开销会增大。
   * 用户认证之后，服务端在内存中做认证记录，如果下次请求，还需要去访问有记录的服务器才行，这对于分布式的应用来说，体验不好。
   * 基于Cookie识别用户，如果Cookie被抓包到，容易造成跨站请求伪造的攻击。

基于jwt的认证

1. 认证方式：前端携带用户名密码发送到后端接口，后端核对用户名和密码成功后，会将用户的id等信息，作为payload，将其与header分别进行base64加密之后，拼接起来，进行加密，形成一种格式xxx.xxx.xxx的jwt字符串（三部分组成，header、payload、signature，中间用点隔开），返回给前端。前端可以将该信息存储在localStorage或者sessionStorage中，请求时，一般将jwt放入请求头里authorization中。后端会校验jwt是否正确、是否过期，然后拿jwt内部包含的用户信息去进行其他认证通过后的操作。
2. 优点
   * 简洁：jwt可以放在url、请求体、请求头中发送
   * 自包含：payload中包含了用户所需要的所有信息，避免了多次查询数据库
   * 跨语言：jwt是以json的格式保存在客户端的，原则上支持所有形式
   * 分布式：不需要在服务端保存会话信息，特别适合分布式微服务

# 二、JWT结构

jwt的组成

1. header：标头
2. payload：负载
3. signature：签名

jwt通常如下所示，xxxx.xxxx.xxxx，也就是header.payload.signature

## 2.1 header

header通常是由两部分组成json。然后进行Base64编码，组成jwt的第一部分

1. 令牌的类型
2. 使用的签名算法，例如HmacSha256、Rsa。jwt推荐使用HmacSha256算法

> header中也可以加入一些自定义的内容

例如下面的这种格式

```json
{
    "alg": "HS256",
    "typ": "JWT"
}
```

> jwt为了保证编码的简短，一般会简写过长的单词，如：
>
> alg：algorithm，算法
>
> typ：type，类型

## 2.2 payload

payload主要存储用户和其他的一些数据，但是不能存放敏感信息，如密码。然后进行Base64编码，组成jwt的第二部分

payload在java代码里面也叫做claim，即声明。

```json
{
    "userId": "000001",
    "userName": "CCC",
    "admin": 1
}
```



## 2.3 signature

header与payload是通过Base64进行编码的，前端是可以解开知道里面的内容的。

signature就是使用header中提供的算法，对经过Base64进行编码过的header和payload，使用我们提供的密钥来进行签名。签名的作用是保证jwt没有被篡改过，如果将signature解密后，与headerBase64.payloadBase64不一致，就是被篡改过的。signature是jwt的第三部分。

如：

```java
String headerPayload=base64UrlEncodeHeader+"."+base64UrlEncodePayload;
String signature=HMACSHA256(headerPayload,secret)
```

jwt最终的结构，就是将header的base64，payload的base64，signature加密后的值，用`.`来分割，拼成一串字符串。

![](https://meethigher.top/blog/2021/jwt/1.jpg)

# 三、使用JWT

## 3.1 上手

引入依赖

```xml
<!-- https://mvnrepository.com/artifact/com.auth0/java-jwt -->
<dependency>
    <groupId>com.auth0</groupId>
    <artifactId>java-jwt</artifactId>
    <version>3.18.2</version>
</dependency>
```

生成jwt

```java
public class GenerateJWT {
    public static void main(String[] args) {
        Map<String,Object> map=new HashMap<>();
        //获取过去时间
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.SECOND,10);
        String jwtToken = JWT.create()
                //header，map里面传值，表示在除type、algorithm之外，添加自定义的内容
                .withHeader(map)
                //payload
                .withClaim("userId", "000001")
                .withClaim("userName", "CCC")
                .withClaim("admin", 1)
                //指定过期时间
                .withExpiresAt(calendar.getTime())
                //signature
                .sign(Algorithm.HMAC384("meethigher"));
        System.out.println(jwtToken);
    }
}
```

校验jwt

```java
public class VerifyJWT {
    public static void main(String[] args) {
        Map<String,Object> map=new HashMap<>();
        //获取过去时间
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.SECOND,60);
        String jwtToken = JWT.create()
                //header，map里面传值，表示在除type、algorithm之外，添加自定义的内容
                .withHeader(map)
                //payload
                .withClaim("userId", "000001")
                .withClaim("userName", "CCC")
                .withClaim("admin", 1)
                //指定过期时间
                .withExpiresAt(calendar.getTime())
                //signature
                .sign(Algorithm.HMAC384("meethigher"));
        System.out.println(jwtToken);
        //创建验证对象
        JWTVerifier verifier = JWT.require(Algorithm.HMAC384("meethigher")).build();
        DecodedJWT decodedJWT = verifier.verify(jwtToken);
        System.out.println(decodedJWT.getClaim("userId").asString());
        System.out.println(decodedJWT.getClaim("userName").asString());
        //注意，如果是个整型，用asString会返回一个null。可以点进去查看源码注释
        System.out.println(decodedJWT.getClaim("admin").asInt());
        System.out.println(decodedJWT.getExpiresAt());
    }
}
```

## 3.2 封装工具类

JWTUtils.java

```java
public class JWTUtils {
    private static String SECRET = "meethigher";

    /**
     * 传入Payload生成jwt
     *
     * @param map
     * @return
     */
    public static String getToken(Map<String, String> map) {
        Calendar calendar = Calendar.getInstance();
        //7天过期
        calendar.add(Calendar.DAY_OF_MONTH, 7);

        //第一种存payload方式：遍历map存入
//        JWTCreator.Builder builder = JWT.create();
//        map.forEach(builder::withClaim);
        //第二种存payload方式：直接放map,底层采用的也是第一种方式
        return JWT.create()
                .withPayload(map)
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
```

## 3.3 整合springboot

关键代码

pom.xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.3.1.RELEASE</version>
        <relativePath/> <!-- lookup parent from repository -->
    </parent>
    <groupId>top.meethigher</groupId>
    <artifactId>springboot-jwt</artifactId>
    <version>1.0.0</version>
    <name>springboot-jwt</name>
    <description>chenchuancheng&apos;s demo</description>
    <properties>
        <java.version>1.8</java.version>
    </properties>
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
        <!-- https://mvnrepository.com/artifact/org.xerial/sqlite-jdbc -->
        <dependency>
            <groupId>org.xerial</groupId>
            <artifactId>sqlite-jdbc</artifactId>
            <version>3.34.0</version>
        </dependency>
        <!-- https://mvnrepository.com/artifact/com.github.gwenn/sqlite-dialect -->
        <dependency>
            <groupId>com.github.gwenn</groupId>
            <artifactId>sqlite-dialect</artifactId>
            <version>0.1.2</version>
        </dependency>
        <dependency>
            <groupId>io.springfox</groupId>
            <artifactId>springfox-boot-starter</artifactId>
            <version>3.0.0</version>
        </dependency>
        <dependency>
            <groupId>io.springfox</groupId>
            <artifactId>springfox-swagger-ui</artifactId>
            <version>3.0.0</version>
        </dependency>
        <!-- https://mvnrepository.com/artifact/com.auth0/java-jwt -->
        <dependency>
            <groupId>com.auth0</groupId>
            <artifactId>java-jwt</artifactId>
            <version>3.18.2</version>
        </dependency>


    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>

</project>
```

application.yml

```yaml
#logging:
#  config: classpath:logback.xml
server:
  port: 9090
  ssl:
    enabled: false
spring:
  datasource:
    driver-class-name: org.sqlite.JDBC
    url: jdbc:sqlite:D:/sqliteData/jwt.db
  jpa:
    database-platform: org.sqlite.hibernate.dialect.SQLiteDialect
    hibernate:
      ddl-auto: update
      naming:
        physical-strategy: org.hibernate.boot.model.naming.PhysicalNamingStrategyStandardImpl
    show-sql: true
  mvc:
    async:
      request-timeout: 30000
```

SwaggerConfig

```java
@Configuration
public class SwaggerConfig {
    //配置swagger的实例
    @Bean
    public Docket api() {
        return new Docket(DocumentationType.SWAGGER_2)
                .apiInfo(apiInfo())
                .select()
                //只显示包含Api注解的，如果不加这个，会有basic-error-controller显示
                .apis(RequestHandlerSelectors.withClassAnnotation(Api.class))
                .paths(PathSelectors.any())
                .build();
    }
    private ApiInfo apiInfo() {
        return new ApiInfoBuilder()
                .title("API接口文档")
                .description("API接口文档")
                .version("1.0")
                .build();
    }

}
```

InterceptorConfig

```java
@Configuration
public class InterceptorConfig implements WebMvcConfigurer {

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new LoginInterceptor())
                .addPathPatterns("/user/*")
                .excludePathPatterns("/user/login");
    }
}
```

LoginInterceptor

```java
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
```