package top.meethigher.springbootjwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import top.meethigher.springbootjwt.entity.User;

/**
 * UserRepository
 *
 * @author chenchuancheng
 * @github https://github.com/meethigher
 * @blog https://meethigher.top
 * @time 2021/11/13 15:24
 */
public interface UserRepository extends JpaRepository<User,String>, JpaSpecificationExecutor<User> {
}
