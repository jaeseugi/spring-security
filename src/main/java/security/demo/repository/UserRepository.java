package security.demo.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.util.StringUtils;
import security.demo.model.User;

/**
 * packageName :  security.demo.repository
 * fileName : UserRepository
 * author :  wotjr210
 * date : 2022/10/06
 * description :
 * ===========================================================
 * DATE                 AUTHOR                NOTE
 * -----------------------------------------------------------
 * 2022/10/06                wotjr210             최초 생성
 */

// CRUD함수를 JpaRepository가 들고 있습니다.
// @Repository 어노테이션이 없어도 IoC됩니다. 이유는 JpaRepository를 상속했기 때문에..
// 필요한곳에서 주입해서 사용한다.
public interface UserRepository extends JpaRepository<User, Integer> {

    /*
        findBy규칙 → Username문법
        select * from user where username = ?
     */
    public User findByUsername(String username); // Jpa 쿼리 메소드


    /*
        findBy규칙 → Username문법
        select * from user where email = ?
     */
    public User findByEmail(String username);
}
