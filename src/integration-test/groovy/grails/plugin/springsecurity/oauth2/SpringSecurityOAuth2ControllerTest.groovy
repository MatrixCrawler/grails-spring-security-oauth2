package grails.plugin.springsecurity.oauth2

import com.github.scribejava.core.model.OAuth2AccessToken
import grails.plugin.springsecurity.SpringSecurityService
import grails.plugin.springsecurity.oauth2.exception.OAuth2Exception
import grails.plugin.springsecurity.oauth2.token.OAuth2SpringToken
import grails.plugin.springsecurity.userdetails.GrailsUser
import grails.test.mixin.TestFor
import org.springframework.security.authentication.AuthenticationEventPublisher
import spock.lang.Specification
import spock.lang.Unroll

/**
 * Always code as if the guy who ends up maintaining your code
 * will be a violent psychopath that knows where you live.
 *
 * - John Woods
 *
 * Created on 21.06.2016
 * @author MatrixCrawler
 */
@TestFor(SpringSecurityOAuth2Controller)
class SpringSecurityOAuth2ControllerTest extends Specification {

    @Unroll
    def "Registration command objects for #loginId validating correctly"() {

        given: "a mocked command object"
        def createAccountCommandMock = mockCommandObject(OAuth2CreateAccountCommand)
        createAccountCommandMock.springSecurityOauth2BaseService = [usernameTaken: { u -> false }]

        and: "a set of initial values from the spock test"
        createAccountCommandMock.username = loginId
        createAccountCommandMock.password1 = password
        createAccountCommandMock.password2 = passwordRepeat

        when: "the validator is invoked"
        def isValidRegistration = createAccountCommandMock.validate()

        then: "the appropriate fields are flagged as errors"
        isValidRegistration == anticipatedValid
        createAccountCommandMock.errors.getFieldError(fieldInError)?.code == errorCode

        where:
        loginId | password   | passwordRepeat | anticipatedValid | fieldInError | errorCode
        "glen"  | "password" | "no-match"     | false            | "password2"  | "OAuthCreateAccountCommand.password.error.mismatch"
        "glen"  | "!QAZxsw"  | "!QAZxsw"      | false            | "password1"  | "minSize.notmet"
        "glen"  | "password" | "password"     | false            | "password1"  | "OAuthCreateAccountCommand.password.error.strength"
        "peter" | "!QAZxsw2" | "!QAZxsw2"     | true             | null         | null
        "a"     | "password" | "password"     | false            | "username"   | "minSize.notmet"

    }

    def "authenticate should throw exception if request is missing provider"() {
        given:
        params.provider = provider
        def springSecurityOauth2BaseService = Mock(SpringSecurityOauth2BaseService)
        controller.springSecurityOauth2BaseService = springSecurityOauth2BaseService

        when:
        controller.authenticate()

        then:
        thrown OAuth2Exception

        where:
        provider | _
        ''       | _
        '  '     | _
        null     | _
    }

    def "onSuccess should throw exception if request is missing data"() {
        given:
        params.provider = provider
        def springSecurityOauth2BaseService = Mock(SpringSecurityOauth2BaseService)
        controller.springSecurityOauth2BaseService = springSecurityOauth2BaseService

        when:
        controller.onSuccess()

        then:
        thrown OAuth2Exception

        where:
        provider | _
        ''       | _
        null     | _
    }

    def "onSuccess should throw exception if session is missing data"() {
        given:
        params.provider = provider
        def springSecurityOauth2BaseService = Mock(SpringSecurityOauth2BaseService)
        controller.springSecurityOauth2BaseService = springSecurityOauth2BaseService

        when:
        controller.onSuccess()

        then:
        1 * springSecurityOauth2BaseService.sessionKeyForAccessToken(provider) >> { 'OAuth2: access - t:' + provider }
        thrown OAuth2Exception

        where:
        provider   | _
        'facebook' | _
        'google'   | _
        'somewhat' | _
    }

    // now askToLinkOrCreateAccountUri is hardcoded, so this test is redundant
    def "onSuccess should throw exception if askToLinkOrCreateAccountUri is not set"() {
        given:
        OAuth2SpringToken authToken = Mock(OAuth2SpringToken)
        params.provider = provider
        def springSecurityOauth2BaseService = Mock(SpringSecurityOauth2BaseService)
        controller.springSecurityOauth2BaseService = springSecurityOauth2BaseService

        def sessionKey = 'OAuth2: access - t:' + provider

        def oAuth2AccessToken = Mock(OAuth2AccessToken)
        session[sessionKey] = oAuth2AccessToken

        when:
        controller.onSuccess()

        then:
        1 * springSecurityOauth2BaseService.sessionKeyForAccessToken(provider) >> { sessionKey }
        1 * springSecurityOauth2BaseService.createAuthToken(provider, session[sessionKey]) >> { authToken }
        1 * springSecurityOauth2BaseService.getAskToLinkOrCreateAccountUri() >> { null }
        thrown OAuth2Exception

        where:
        provider   | _
        'facebook' | _
    }

    def "onSuccess should redirect to askToLinkOrCreateAccountUri if the user is not logged in"() {
        given:
        OAuth2SpringToken authToken = Mock(OAuth2SpringToken)
        params.provider = provider
        def springSecurityOauth2BaseService = Mock(SpringSecurityOauth2BaseService)
        controller.springSecurityOauth2BaseService = springSecurityOauth2BaseService
        def sessionKey = 'OAuth2: access - t:' + provider
        springSecurityOauth2BaseService.sessionKeyForAccessToken(provider) >> { sessionKey }
        def oAuth2AccessToken = Mock(OAuth2AccessToken)
        session[sessionKey] = oAuth2AccessToken
        springSecurityOauth2BaseService.createAuthToken(provider, session[sessionKey]) >> { authToken }
        springSecurityOauth2BaseService.getAskToLinkOrCreateAccountUri() >> { "/askToLinkOrCreateAccountUri" }
        controller.springSecurityOauth2BaseService = springSecurityOauth2BaseService
        and:
        controller.onSuccess()
        expect:
        response.status == responseCode
        response.redirectedUrl == "/askToLinkOrCreateAccountUri"
        where:
        provider   | responseCode
        'facebook' | 302
    }

    def "onSuccess should redirect to defaultTargeturl if user is logged in"() {
        given:
        def token = Stub(OAuth2AccessToken) {
            getRawResponse() >> "a=1&b=2"
        }
        OAuth2SpringToken authToken = new TestOAuth2SpringToken(token, false)
        params.provider = provider
        def springSecurityOauth2BaseService = Mock(SpringSecurityOauth2BaseService)
        controller.springSecurityOauth2BaseService = springSecurityOauth2BaseService
        def authenticationEventPublisher = Mock(AuthenticationEventPublisher)
        controller.authenticationEventPublisher = authenticationEventPublisher
        def sessionKey = 'OAuth2: access - t:' + provider
        springSecurityOauth2BaseService.sessionKeyForAccessToken(provider) >> { sessionKey }
        def oAuth2AccessToken = Mock(OAuth2AccessToken)
        session[sessionKey] = oAuth2AccessToken
        springSecurityOauth2BaseService.createAuthToken(provider, session[sessionKey]) >> { authToken }
        springSecurityOauth2BaseService.getAskToLinkOrCreateAccountUri() >> { "/ask" }
        controller.springSecurityOauth2BaseService = springSecurityOauth2BaseService
        controller.springSecurityOauth2BaseService = springSecurityOauth2BaseService
        and:
        controller.onSuccess()
        expect:
        response.status == responseCode
        response.redirectedUrl == controller.getDefaultTargetUrl().uri
        where:
        provider   | responseCode
        'facebook' | 302
    }

    def "linkAccount should return view if user is not logged in"() {
        given:
        def token = Stub(OAuth2AccessToken) {
            getRawResponse() >> "a=1&b=2"
        }
        OAuth2SpringToken authToken = new TestOAuth2SpringToken(token, false)
        session["springSecurityOAuthToken"] = authToken
        def springSecurityService = Mock(SpringSecurityService)
        springSecurityService.isLoggedIn() >> {false}
        controller.springSecurityService = springSecurityService
        when:
        controller.linkAccount()
        then:
        response
        view == '/springSecurityOAuth2/ask'
    }
}

/**
 * A basic implementation for oauth token for a loggedin user.
 */
class TestOAuth2SpringToken extends OAuth2SpringToken {
    TestOAuth2SpringToken(OAuth2AccessToken token, boolean json) {
        super(token, json)
        this.principal = new GrailsUser("username", "password", true, true, true, true, [], 1L)
    }

    String getProviderName() {
        return "provider"
    }

    String getSocialId() {
        return "socialId"
    }

    String getScreenName() {
        return "screenName"
    }
}
