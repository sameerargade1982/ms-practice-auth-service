package com.argade.authservice.security.config;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
@Configuration
@EnableAuthorizationServer
@EnableResourceServer
public class Oauth2AuthorizationServer  extends AuthorizationServerConfigurerAdapter {
//TO DO : add password encoder, tokenstore and tokenenhancer.
	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private UserDetailsService userDetailsService;

	

	// todo: change from inmemory to something else
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

		clients.inMemory().withClient("eagleeye").secret("thisissecret")
		.authorities("ROLE_TRUSTED_CLIENT")
       .authorizedGrantTypes("implicit", "authorization_code", "refresh_token", "password")
       .accessTokenValiditySeconds(600)
       //.scopes("openid")
       .scopes("webclient", "mobileclient")
       .autoApprove(true);
				//
	}
	
	  @Bean
	    public JwtAccessTokenConverter jwtAccessTokenConverter() {
	        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
//	        KeyPair keyPair = new KeyStoreKeyFactory(new ClassPathResource("keystore.jks"), "foobar".toCharArray())
//	            .getKeyPair("test");
//	        converter.setKeyPair(keyPair);
	        return converter;
	    }
	  @Override // [2]
	    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
//	        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
//	        tokenEnhancerChain.setTokenEnhancers(
//	            Arrays.asList(tokenEnhancer(), jwtAccessTokenConverter()));

	        endpoints//.tokenStore(tokenStore())
	            //.tokenEnhancer(tokenEnhancerChain)
	            .authenticationManager(authenticationManager)
	            .userDetailsService(userDetailsService)
	           .accessTokenConverter(jwtAccessTokenConverter());
	    }
	  @Override
	    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
	        oauthServer
	            .tokenKeyAccess("isAnonymous() || hasAuthority('ROLE_TRUSTED_CLIENT')")
	            .checkTokenAccess("isAuthenticated()");
	    }

//	    @Bean
//	    public TokenEnhancer tokenEnhancer() {
//	        return new CustomTokenEnhancer();
//	    }
//
//	    @Bean
//	    public TokenStore tokenStore() {
//	        return new JwtTokenStore(jwtAccessTokenConverter());
//	    }
	    
}
