package backend01.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

	@Autowired
	private DataSource dataSource;

//	@Autowired
//	private AuthenticationManager authenticationManager;

	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		security.allowFormAuthenticationForClients();
		security.checkTokenAccess("isAuthenticated()");
		security.tokenKeyAccess("isAuthenticated()");
	}

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.jdbc(dataSource);
	}

	/**
	 * 关于端点（endpoint），请参考：http://ifeve.com/oauth2-tutorial-6-endpoints/
	 */
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		/**
		 * 必须有这一句，否则client通过/login?code=xxx拿到authorization
		 * code后，无法成功进行下一步，只好重定向到其/login，再重定向到auth
		 * server的/authorize，接着再重定向到client的/login?code=xxx，还是失败，继续重定向到client的/
		 * login，再重定向到auth server的/authorize......如此反复，无限重定向
		 */
//		endpoints.accessTokenConverter(jwtAccessTokenConverter());

//		endpoints.tokenStore(jwtTokenStore());

//		endpoints.tokenStore(redisTokenStore());

		// 此句可以替换上面内容
		endpoints.tokenServices(defaultTokenServices());

		/**
		 * 支持password模式必须配置。否则报{"error":"unsupported_grant_type",
		 * "error_description":"Unsupported grant type: password"}
		 */
//		endpoints.authenticationManager(authenticationManager);
	}

	@Primary
	@Bean
	public DefaultTokenServices defaultTokenServices() {
		DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
//		defaultTokenServices.setTokenStore(jwtTokenStore());
		defaultTokenServices.setTokenStore(redisTokenStore(null));
		defaultTokenServices.setSupportRefreshToken(true); // default is false
		defaultTokenServices.setTokenEnhancer(jwtAccessTokenConverter(null));
		return defaultTokenServices;
	}

	/**
	 * 除此之外，还有JwtTokenStore、InMemoryTokenStore、JdbcTokenStore等等
	 *
	 * @return
	 */
	@Bean
	public RedisTokenStore redisTokenStore(RedisConnectionFactory connectionFactory) {
		RedisTokenStore redisTokenStore = new RedisTokenStore(connectionFactory);
		redisTokenStore.setPrefix("redis_token_store:");
		return redisTokenStore;
	}

	@Bean
	public JwtTokenStore jwtTokenStore() {
		return new JwtTokenStore(jwtAccessTokenConverter(null));
	}

	@Bean
	public JwtAccessTokenConverter jwtAccessTokenConverter(
			@Value("${security.oauth2.resource.jwt.key-value}") String signingKey) {
		JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
		jwtAccessTokenConverter.setSigningKey(signingKey); //  Sets the JWT signing key
		return jwtAccessTokenConverter;
	}

}
