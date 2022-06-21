# spring_security
스프링시큐리티 설정 

# xml 방식으로 시큐리티를 설정하고자 할때

context-security 파일 생성 
```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xmlns:egov-security="http://maven.egovframe.go.kr/schema/egov-security"
	xmlns:security="http://www.springframework.org/schema/security"
	xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans-4.0.xsd
        http://www.springframework.org/schema/security http://www.springframework.org/schema/security/spring-security.xsd
		http://maven.egovframe.go.kr/schema/egov-security http://maven.egovframe.go.kr/schema/egov-security/egov-security-4.0.0.xsd">
		
	<security:http>
		<security:intercept-url pattern="/admin" access="permitAll" />
		<!-- <security:intercept-url pattern="/admin" access="hasRole('ROLE_ADMIN')" /> -->
		<security:intercept-url pattern="/system" access="hasRole('ROLE_ADMIN')" />
		<security:form-login />
	</security:http>
<security:authentication-manager>
	<security:authentication-provider>
		<security:user-service>
			<security:user name="user" password="{noop}password" authorities="ROLE_USER" />
		</security:user-service>
	</security:authentication-provider>
</security:authentication-manager>


</beans>


```
여기서 {noop} 은 패스워드 인코딩 처리없이 하겠다는것이다.

web.xml 에 스프링 시큐리티 필터 체인 걸어주기 

``` xml
  <!--  spring security -->
    <filter>
        <filter-name>springSecurityFilterChain</filter-name>
        <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
    </filter>
    <filter-mapping>
          <filter-name>springSecurityFilterChain</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>
    

```
