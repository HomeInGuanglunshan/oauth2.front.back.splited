package backend02.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

@Configuration
public class TokenServicesConfig {

	@Primary
	@Bean
	public DefaultTokenServices defaultTokenServices() {
		DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
//		defaultTokenServices.setTokenStore(jwtTokenStore());
		defaultTokenServices.setTokenStore(redisTokenStore());
		defaultTokenServices.setSupportRefreshToken(true); // default is false
		defaultTokenServices.setTokenEnhancer(jwtAccessTokenConverter());
		return defaultTokenServices;
	}

	@Autowired
	RedisConnectionFactory connectionFactory;

	/**
	 * 除此之外，还有JwtTokenStore、InMemoryTokenStore、JdbcTokenStore等等
	 *
	 * @return
	 */
	@Bean
	public RedisTokenStore redisTokenStore() {
		RedisTokenStore redisTokenStore = new RedisTokenStore(connectionFactory);
		redisTokenStore.setPrefix("redis_token_store:");
		return redisTokenStore;
	}

	@Bean
	public JwtTokenStore jwtTokenStore() {
		return new JwtTokenStore(jwtAccessTokenConverter());
	}

	@Value("${security.oauth2.resource.jwt.key-value}")
	String signingKey;

	@Bean
	public JwtAccessTokenConverter jwtAccessTokenConverter() {
		JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
		jwtAccessTokenConverter.setSigningKey(signingKey); //  Sets the JWT signing key
		return jwtAccessTokenConverter;
	}

}
