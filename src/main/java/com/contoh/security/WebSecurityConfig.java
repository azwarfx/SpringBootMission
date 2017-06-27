package com.contoh.security;

import java.security.Principal;
import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/",
                        "/plugin/css/bootstrap.min.css",
                        "/plugin/css/modern-business.css",
                        "/plugin/fonts/font-awesome.min.css",
                        "/img/*",
                        "/plugin/js/*",
                        "/adminlte/bootstrap/*",
                        "/adminlte/build/*",
                        "/adminlte/dist/*",
                        "/adminlte/pages/*",
                        "/adminlte/plugins/*",
                        "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.5.0/css/font-awesome.min.css",
                        "https://cdnjs.cloudflare.com/ajax/libs/ionicons/2.0.1/css/ionicons.min.css",
                        "/adminlte/dist/js/app.min.js",
                        "/adminlte/bootstrap/js/bootstrap.min.js",
                        "/adminlte/plugins/jQuery/jquery-2.2.3.min.js",
                        "/adminlte/dist/img/user2-160x160.jpg",
                        "/adminlte/dist/img/*",
                        "/adminlte/dist/img/user2-160x160.jpg",
                        "/adminlte/dist/img/user2-160x160.jpg",
                        "/adminlte/dist/img/user2-160x160.jpg",
                        "/adminlte/dist/css/skins/skin-blue.min.css",
                        "/adminlte/dist/css/AdminLTE.min.css",
                        "/adminlte/bootstrap/css/bootstrap.min.css")
                .permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login")
                .permitAll()
                .and()
                .logout()
                .permitAll();
    }

    /**
     * ini generate mesin
     */
    /**
     * @Autowired public void configureGlobal(AuthenticationManagerBuilder auth)
     * throws Exception { auth .inMemoryAuthentication()
     * .withUser("user").password("password").roles("USER");
    }
     */
    /**
     * Ini dari database
     */
    private String user = "select username,password,active as enabled from "
            + "s_users where username= ?";

    private String auth = "select u.username, r.nama as authority from "
            + "s_users u join s_user_role ur on u.id=ur.id_user join s_roles r on ur.id_role=r.id where "
            + "u.username= ?";

    @Autowired
    private DataSource ds;

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .jdbcAuthentication()
                .dataSource(ds).usersByUsernameQuery(user)
                .authoritiesByUsernameQuery(user);
    }
    
    
}
