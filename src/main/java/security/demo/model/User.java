package security.demo.model;

import lombok.Data;

import javax.persistence.*;
import java.time.LocalDateTime;

/**
 * packageName :  security.demo
 * fileName : User
 * author :  wotjr210
 * date : 2022/10/06
 * description :
 * ===========================================================
 * DATE                 AUTHOR                NOTE
 * -----------------------------------------------------------
 * 2022/10/06                wotjr210             최초 생성
 */

@Entity
@Data
@Table(name = "USERS")
public class User {

    @Id
    @GeneratedValue
    private int id;
    private String username;
    private String password;
    private String email;
    private String role;

    private LocalDateTime createDate;

    public User() {
        createDate = LocalDateTime.now();
    }
}
