//package com.argade.authservice.security.config;
//
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
//import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
//import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
//
//@Configuration
//@EnableResourceServer
//public class Oauth2ResourceServer  extends ResourceServerConfigurerAdapter {
//	
//	//There should be a userdetails service to check authentication
//	//for refresh token but mostly because we are not going to use a 
//	//authenticationmanager we don't need userdetails service. todo change this
//	// to imeplement authenticationmanager
//	 @Override
//	    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
//	        resources.resourceId("ms-backend");
//	    }
//	 
////	 @Override
////	public void configure(HttpSecurity http) throws Exception {
////	        http.requestMatchers()
////	            .antMatchers("/login", "/oauth/token")
////	            .and()
////	            .authorizeRequests()
////	            .anyRequest().authenticated()
////	            .and()
////	            .formLogin().permitAll();
////	    }
////	
//
////	    @Override
////	    public void configure(HttpSecurity http) throws Exception {
////	        http
////	            .httpBasic().disable()
////	            .sessionManagement()
////	            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
////	            .and()
////	            .requestMatchers().anyRequest()
////	            .and()
////	            .anonymous()
////	            .and()
////	            .authorizeRequests()
////	            .antMatchers("/oauth/**").permitAll()
////	            .antMatchers("/api/**").permitAll()
////	            .antMatchers("/test").authenticated()
////	           
////	            .antMatchers("/actuator").permitAll()
////	            .antMatchers("/autoconfig").permitAll()
////	            .antMatchers("/beans").permitAll()
////	            .antMatchers("/configprops").permitAll()
////	            .antMatchers("/dump").permitAll()
////	            .antMatchers("/env").permitAll()
////	            .antMatchers("/flyway").permitAll()
////	            .antMatchers("/health").permitAll()
////	            .antMatchers("/info").permitAll()
////	            .antMatchers("/liquibase").permitAll()
////	            .antMatchers("/metrics").permitAll()
////	            .antMatchers("/mappings").permitAll()
////	            .antMatchers("/shutdown").denyAll()
////	            .antMatchers("/trace").permitAll()
////	            .antMatchers("/docs").permitAll()
////	            .antMatchers("/heapdump").permitAll()
////	            .antMatchers("/jolokia").permitAll()
////	            .antMatchers("/logfile").permitAll()
////
////	            .anyRequest().permitAll()
////	            .and()
////	            .csrf().disable()
////	            .exceptionHandling()
////	            .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
////	            .and()
////	            .logout().logoutUrl("/logout").logoutSuccessUrl("/");
////	    }
//}
