# spring_security
스프링시큐리티 설정 

# 스프링 시큐리티 (XML방식) 에서 다중 auth 에게 권한을 부여하고 싶을때 

# xml 방식으로 시큐리티를 설정하고자 할때
```xml
  <security:intercept-url pattern="/mypage_admin/" access="hasAnyRole("ROLE_MEMBER", "ROLE_ADMIN")/>

```
hasAnyRole 을 사용 

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

# 최종 
``` xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xmlns:egov-security="http://maven.egovframe.go.kr/schema/egov-security"
	xmlns:security="http://www.springframework.org/schema/security"
	xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans-4.0.xsd
        http://www.springframework.org/schema/security http://www.springframework.org/schema/security/spring-security.xsd
		http://maven.egovframe.go.kr/schema/egov-security http://maven.egovframe.go.kr/schema/egov-security/egov-security-4.0.0.xsd">
		
<security:http use-expressions="true">
	<security:intercept-url pattern="/admin" access="permitAll" />
	<security:intercept-url pattern="/page" access="permitAll" />
	 <security:intercept-url pattern="/system/addUser.do" access="hasRole('ROLE_ADMIN')" />
	<security:intercept-url pattern="/system" access="hasRole('ROLE_ADMIN')" />
	 
	

		<!-- <security:intercept-url pattern="/admin" access="hasRole('ROLE_ADMIN')" /> -->
	<security:form-login default-target-url="/" 
							authentication-failure-url="/login/loginForm?error"
							username-parameter="id"
							password-parameter="password" 
							login-processing-url="/login/login.do"
							/>
	<security:logout logout-url="/logout" logout-success-url="/login/loginForm" />
	<security:access-denied-handler error-page="/login/accessDenied"/>
</security:http>
<!-- 
	access= "permitAll" ( 누구나 접근 가능 )
			"hasRole('ADMIN')" (ADMIN 권한을 가지고 있는 유저만 접근 가능)
			"hasAnyRole('USER','ADMIN') (USER 또는 ADMIN 권한을 가지고 있는 유저는 접근 가능)
 -->
 
 <!-- 
 	login-page : 로그인 페이지 URL
 	default-target-url : 로그인 후 보여질 페이지
 	authentication-failure-url : 로그인 실패시 보여질 페이지
 	username-parameter : 아이디 입력 필드에 사용될 name
 	password-parameter : 비밀번호 입력 필드에 사용될 password
  -->
	  
  <!-- 
  	logout-url : 로그아웃 페이지 URL
  	logout-success-url : 로그아웃에 성공하였을 때 보여질 페이지
   -->
<!-- provider -->

	<!-- <bean id="loginService" class="egovframework.system.login.service.LoginService"/> -->
<!-- <security:authentication-provider  user-service-ref="loginService"/>  -->
<security:authentication-manager>

	<security:authentication-provider>
            <!-- <user-service>
               <user name="admin" password="1234" authorities="ROLE_USER, ROLE_ADMIN" />
               <user name="guest" password="1234" authorities="ROLE_USER" />
               <user name="guest2" password="a1234" authorities="ROLE_USER" />
            </user-service> -->
            <security:jdbc-user-service data-source-ref="dataSource"
            	users-by-username-query="SELECT mber_id as id, 
            									password as password,
            									1 as enabled
            							   FROM comtngnrlmber WHERE mber_id=?"
            	authorities-by-username-query="
										SELECT mber_id as mber_id,
            										  CASE WHEN USERGRADE='01' THEN 'ROLE_ADMIN' 
            										       ELSE 'ROLE_USER'
            										       END authority
            								     FROM comtngnrlmber WHERE mber_id=?"            
            />
        </security:authentication-provider> 
</security:authentication-manager>



	

</beans>


```
