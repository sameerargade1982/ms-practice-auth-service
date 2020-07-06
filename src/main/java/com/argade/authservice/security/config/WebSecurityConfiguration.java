package com.argade.authservice.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;

@EnableWebSecurity
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {
	private static final String ADMIN = "ADMIN";
	private static final String USER = "USER";

	@Autowired
	private UserDetailsService userDetailsService;
	
	// private CustomPasswordEncoder customPasswordEncoder;
	
//	 @Autowired
//	    public WebSecurityConfiguration(CustomUserDetailsService customUserDetailsService,
//	                          CustomPasswordEncoder customPasswordEncoder) {
//	        this.customUserDetailsService = customUserDetailsService;
//	        this.customPasswordEncoder = customPasswordEncoder;
//	    }

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService);
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
//		http.authorizeRequests().antMatchers("/admin").hasRole(ADMIN)
//			.antMatchers("/user").hasAnyRole(ADMIN, USER)
//			.antMatchers("/all").permitAll()
//			.and().formLogin();
		http
        .httpBasic().disable()
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        .anonymous()
        .and()
        .authorizeRequests()
        .antMatchers("/oauth/**").permitAll()
        .antMatchers("/api/**").permitAll()
        .antMatchers("/test").authenticated()

        .antMatchers("/actuator").permitAll()
        .antMatchers("/autoconfig").permitAll()
        .antMatchers("/beans").permitAll()
        .antMatchers("/configprops").permitAll()
        .antMatchers("/dump").permitAll()
        .antMatchers("/env").permitAll()
        .antMatchers("/flyway").permitAll()
        .antMatchers("/health").permitAll()
        .antMatchers("/info").permitAll()
        .antMatchers("/liquibase").permitAll()
        .antMatchers("/metrics").permitAll()
        .antMatchers("/mappings").permitAll()
        .antMatchers("/shutdown").denyAll()
        .antMatchers("/trace").permitAll()
        .antMatchers("/docs").permitAll()
        .antMatchers("/heapdump").permitAll()
        .antMatchers("/jolokia").permitAll()
        .antMatchers("/logfile").permitAll()

        .anyRequest().permitAll()
        .and()
        .csrf().disable()
        .exceptionHandling()
        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
        .and()
        .logout().logoutUrl("/logout").logoutSuccessUrl("/");
	}
	
//	 @Override
//	    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//	        auth.userDetailsService(this.customUserDetailsService)
//	            .passwordEncoder(customPasswordEncoder);
//	    }
	
//	  @Override
//	    @Bean
//	    public AuthenticationManager authenticationManagerBean() throws Exception {
//	        return super.authenticationManagerBean();
//	    }
//
//	    @Override
//	    @Bean
//	    public UserDetailsService userDetailsServiceBean() throws Exception {
//	        return super.userDetailsServiceBean();
//	    }

}
