---
title: Spring GateWay OAuth2ResourceServer 配置ServerHttpSecurity中的hasRole 无效的问题
date:  2020-03-25 11:54:21 +0800
haveToc: true
category:
tags: 
excerpt:
---
# 问题
当gateway充当OAuth2ResourceServer的时候，会出现hasRole配置无效的问题。

原因来自于`ServerHttpSecurity.OAuth2ResourceServerSpec.JwtSpec`中默认的`ReactiveAuthenticationManager`没有将jwt中authorities 的负载部分当做Authentication的权限。

简而言之，我们需要把jwt 的Claim中authorities的值加入 这里有个人提出了这个问题，但是官方认为仅仅使用`scope``scp`这两个字段当做权限就足够了[github issue](https://github.com/spring-projects/spring-security-oauth/issues/1659)

# 解决方案
我们重新定义一个`ReactiveAuthenticationManager`权限管理器 默认的权限管理器使用`jwtGrantedAuthoritiesConverter`作为默认的转换器，就是这个转换器默认只读取"scope", "scp"这两个作为权限。

## JwtGrantedAuthoritiesConverter源码
来看源码，源码不长。
`convert`方法可以理解为转换器的调用入口，从这个方法开始看
```
/**
 * Extracts the {@link GrantedAuthority}s from scope attributes typically found in a
 * {@link Jwt}.
 *
 * @author Eric Deandrea
 * @since 5.2
 */
public final class JwtGrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
	private static final String DEFAULT_AUTHORITY_PREFIX = "SCOPE_";

	private static final Collection<String> WELL_KNOWN_AUTHORITIES_CLAIM_NAMES =
			Arrays.asList("scope", "scp");

	private String authorityPrefix = DEFAULT_AUTHORITY_PREFIX;

	private String authoritiesClaimName;

	/**
	 * Extract {@link GrantedAuthority}s from the given {@link Jwt}.
	 *
	 * @param jwt The {@link Jwt} token
	 * @return The {@link GrantedAuthority authorities} read from the token scopes
	 */
	@Override
	public Collection<GrantedAuthority> convert(Jwt jwt) {
		Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
		for (String authority : getAuthorities(jwt)) {
			grantedAuthorities.add(new SimpleGrantedAuthority(this.authorityPrefix + authority));
		}
		return grantedAuthorities;
	}

	/**
	 * Sets the prefix to use for {@link GrantedAuthority authorities} mapped by this converter.
	 * Defaults to {@link JwtGrantedAuthoritiesConverter#DEFAULT_AUTHORITY_PREFIX}.
	 *
	 * @param authorityPrefix The authority prefix
	 * @since 5.2
	 */
	public void setAuthorityPrefix(String authorityPrefix) {
		Assert.hasText(authorityPrefix, "authorityPrefix cannot be empty");
		this.authorityPrefix = authorityPrefix;
	}

	/**
	 * Sets the name of token claim to use for mapping {@link GrantedAuthority authorities} by this converter.
	 * Defaults to {@link JwtGrantedAuthoritiesConverter#WELL_KNOWN_AUTHORITIES_CLAIM_NAMES}.
	 *
	 * @param authoritiesClaimName The token claim name to map authorities
	 * @since 5.2
	 */
	public void setAuthoritiesClaimName(String authoritiesClaimName) {
		Assert.hasText(authoritiesClaimName, "authoritiesClaimName cannot be empty");
		this.authoritiesClaimName = authoritiesClaimName;
	}

	private String getAuthoritiesClaimName(Jwt jwt) {

		if (this.authoritiesClaimName != null) {
			return this.authoritiesClaimName;
		}

		for (String claimName : WELL_KNOWN_AUTHORITIES_CLAIM_NAMES) {
			if (jwt.containsClaim(claimName)) {
				return claimName;
			}
		}
		return null;
	}

	private Collection<String> getAuthorities(Jwt jwt) {
		String claimName = getAuthoritiesClaimName(jwt);

		if (claimName == null) {
			return Collections.emptyList();
		}

		Object authorities = jwt.getClaim(claimName);
		if (authorities instanceof String) {
			if (StringUtils.hasText((String) authorities)) {
				return Arrays.asList(((String) authorities).split(" "));
			} else {
				return Collections.emptyList();
			}
		} else if (authorities instanceof Collection) {
			return (Collection<String>) authorities;
		}

		return Collections.emptyList();
	}
}
```
其实是`getAuthorities()`这个方法是核心。看代码比看描述更快能懂。

而且根据源码我们发现，这个转换器`setAuthoritiesClaimName`方法是可以自定义`AuthoritiesClaimName`。注解清晰的写明了设置用于映射权限（Authorities）token负载（token claim）的名字。

这下就简单好办了。

我们甚至不用自己写一个转换器

## 自定义ReactiveAuthenticationManager

```
......

private final
	OAuth2ResourceServerProperties.Jwt Properties;
	
......

ReactiveAuthenticationManager getAuthenticationManager() {
		NimbusReactiveJwtDecoder nimbusReactiveJwtDecoder = new NimbusReactiveJwtDecoder(Properties.getJwkSetUri());
		JwtReactiveAuthenticationManager jwtReactiveAuthenticationManager = new JwtReactiveAuthenticationManager(nimbusReactiveJwtDecoder);

		JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
		jwtGrantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");
		jwtGrantedAuthoritiesConverter.setAuthoritiesClaimName("authorities");

		JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
		jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);

		ReactiveJwtAuthenticationConverterAdapter reactiveJwtAuthenticationConverterAdapter = new ReactiveJwtAuthenticationConverterAdapter(jwtAuthenticationConverter);

		jwtReactiveAuthenticationManager.setJwtAuthenticationConverter(reactiveJwtAuthenticationConverterAdapter);
		return jwtReactiveAuthenticationManager;
	}
```
并且在设置ServerHttpSecurity的时候添加上一句

```
ServerHttpSecurity.OAuth2ResourceServerSpec.JwtSpec jwtSpec = http.oauth2ResourceServer().jwt();
		jwtSpec.authenticationManager(getAuthenticationManager());
```
# 完整配置代码

```
/**
 * <p>Class: ResourceServerConfigurer</p>
 *
 * @author GodDai
 * @version 1.0.0
 * @since 2020/2/28 11:52
 */
@EnableWebFluxSecurity
public class ResourceServerConfigurer {
	private final
	OAuth2ResourceServerProperties.Jwt Properties;

	@Autowired
	public ResourceServerConfigurer(OAuth2ResourceServerProperties Properties) {
		this.Properties = Properties.getJwt();
	}

	@Bean
	public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
		http.authorizeExchange()
				//允许所有options
				.pathMatchers(HttpMethod.OPTIONS).permitAll()
				//设置需要验证path
				//注意！ hasrole里面的值必须和jwt负载的值一致
				.pathMatchers("/api/admin/**").hasRole("ROLE_ADMIN")
				//其他的就都允许
				.pathMatchers("/**").permitAll()
				.anyExchange().authenticated()
				.and().cors().disable()
				.csrf().disable();

		ServerHttpSecurity.OAuth2ResourceServerSpec.JwtSpec jwtSpec = http.oauth2ResourceServer().jwt();
		jwtSpec.authenticationManager(getAuthenticationManager());
		
		SecurityWebFilterChain chain = http.build();
		return chain;
	}

	ReactiveAuthenticationManager getAuthenticationManager() {
		NimbusReactiveJwtDecoder nimbusReactiveJwtDecoder = new NimbusReactiveJwtDecoder(Properties.getJwkSetUri());
		JwtReactiveAuthenticationManager jwtReactiveAuthenticationManager = new JwtReactiveAuthenticationManager(nimbusReactiveJwtDecoder);

		JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
		jwtGrantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");
		jwtGrantedAuthoritiesConverter.setAuthoritiesClaimName("authorities");

		JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
		jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);

		ReactiveJwtAuthenticationConverterAdapter reactiveJwtAuthenticationConverterAdapter = new ReactiveJwtAuthenticationConverterAdapter(jwtAuthenticationConverter);

		jwtReactiveAuthenticationManager.setJwtAuthenticationConverter(reactiveJwtAuthenticationConverterAdapter);
		return jwtReactiveAuthenticationManager;
	}

}

```
注意！ hasrole里面的值必须和jwt负载的值一致。[在线debugjwt](https://jwt.io/)

不要看全篇代码几乎没有什么描述，那是因为描述太不够清晰，请给你自己一点时间看看源码和注释，非常容易懂

本篇方法纯粹我自己瞎摸索的，希望各位大佬能够多多指教和指出其中错误，以免误人子弟。