//
// SecureImage
//
// Copyright © 2018 Province of British Columbia
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at 
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Created by Jason Leach on 2018-02-02.
//

import Foundation

public typealias AuthenticationCompleted = (_ credentials: Credentials?, _ error: Error?) -> Void

public class AuthServices: NSObject {

    private var baseUrl: URL
    private var redirectUri: String
    private var clientId: String
    public private(set) var credentials: Credentials? = {
        return Credentials.loadFromStoredCredentials()
    }()
    public var onAuthenticationCompleted: AuthenticationCompleted?
    
    public init(baseUrl: URL, redirectUri: String, clientId: String) {
        
        self.baseUrl = baseUrl
        self.redirectUri = redirectUri
        self.clientId = clientId

        super.init()
    }

    public func isAuthenticated() -> Bool {

        guard let credentials = credentials, !credentials.isExpired() else {
            return false
        }
        
        return true
    }
    
    public func viewController(completion: AuthenticationCompleted? = nil) -> AuthViewController {
     
        let url = baseUrl.appendingPathComponent(Constants.API.auth)
        let avc = AuthViewController(authUrl: url, redirectUri: redirectUri, clientId: clientId, responseType: Constants.API.authenticationResponseType)
        avc.delegate = self
        onAuthenticationCompleted = completion
        
        return avc
    }

    public func exchange(_ oneTimeCode: String, completion: @escaping (Credentials?, Error?) -> Void) {
        
        let url = baseUrl.appendingPathComponent(Constants.API.token)
        KeycloakAPI.exchange(oneTimeCode: oneTimeCode, url: url, grantType: Constants.GrantType.authorizationCode.rawValue, redirectUri: redirectUri, clientId: clientId, completionHandler: completion)
    }
    
    public func refreshCredientials(completion: @escaping (Credentials?, Error?) -> Void) {
        
        guard let credentials = credentials else {
            completion(nil, AuthenticationError.credentialsUnavailable)
            return
        }
        
        if credentials.isExpired() {
            completion(nil, AuthenticationError.expired)
            return
        }
        
        let url = baseUrl.appendingPathComponent(Constants.API.token)
        KeycloakAPI.refresh(credentials: credentials, url: url, grantType: Constants.GrantType.refreshToken.rawValue, redirectUri: redirectUri, clientId: clientId, completionHandler: completion)
    }
    
    public func logout() {
        
        guard let credentials = credentials else {
            return
        }
        
        credentials.remove();
        self.credentials = nil
    }
}

// MARK: AuthenticationDelegate
extension AuthServices: AuthenticationDelegate {
    
    public func authenticationSucceded(oneTimeCode: String) {
        
        exchange(oneTimeCode) { (credentials: Credentials?, error: Error?) in

            guard let credentials = credentials else {
                
                self.onAuthenticationCompleted?(nil, AuthenticationError.unableToExchangeOneTimeCodeForToken)
                return
            }
            
            self.onAuthenticationCompleted?(credentials, nil)
        }
    }
    
    public func authenticationFailed(error: Error) {
        onAuthenticationCompleted?(nil, error)
    }
}
