package com.learning.demo.controller;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableWebSecurity
public class MySercurityConfig extends WebSecurityConfigurerAdapter {


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // super.configure(http);
        // 定制请求授权的规则
        http.authorizeRequests().antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("VIP1")
                .antMatchers("/level2/**").hasRole("VIP2")
                .antMatchers("/level3/**").hasRole("VIP3");
        // 开启自动配置的登录功能,
        http.formLogin().usernameParameter("user").passwordParameter("pwd").loginPage("/userlogin");
        //http.formLogin();
        http.rememberMe().rememberMeParameter("remember");


        // 开启自动配置的注销功能，如果注销成功返回“/”页
        http.logout().logoutSuccessUrl("/");
    }
    // 自定义认e证规则
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        super.configure(auth);
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                .withUser("human").password(new BCryptPasswordEncoder().encode("123456")).roles("VIP1")
                .and()
                .withUser("angle").password(new BCryptPasswordEncoder().encode("123456")).roles("VIP1", "VIP2")
                .and()
                .withUser("god").password(new BCryptPasswordEncoder().encode("123456")).roles("VIP1", "VIP2", "VIP3");

    }
}
