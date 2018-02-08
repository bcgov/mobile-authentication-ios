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
// Created by Jason Leach on 2018-02-01.
//

import Foundation
import SwiftKeychainWrapper
import SwiftKeychainWrapper

public struct Credentials {
    
    let tokenType: String
    let refreshToken: String
    let accessToken: String
    let sessionState: String
    let refreshExpiresIn: Int
    let notBeforePolicy: Int
    let tokenId: String
    let expiresIn: Int
    internal let props: [String : Any]

    static func loadFromStoredCredentials() -> Credentials? {
        
        if let json = Credentials.load() {
            return Credentials(withJSON: json)
        }
        
        return nil
    }
    
    init(withJSON data: [String: Any]) {
        
        tokenType = data["token_type"] as! String
        refreshToken = data["refresh_token"] as! String
        accessToken = data["access_token"] as! String
        sessionState = data["session_state"] as! String
        refreshExpiresIn = data["refresh_expires_in"] as! Int   // in sec
        notBeforePolicy = data["not-before-policy"] as! Int
        tokenId = data["id_token"] as! String
        expiresIn = data["expires_in"] as! Int                  // in sec
        
        props = ["token_type": tokenType, "refresh_token": refreshToken, "access_token": accessToken, "session_state": sessionState, "refresh_expires_in": refreshExpiresIn, "not-before-policy": notBeforePolicy, "id_token": tokenId, "expires_in": expiresIn]

        print(accessToken)
        save()
    }

    internal func authTokenExpirationDate() -> Date {

        return Date().addingTimeInterval(Double(expiresIn))
    }
    
    internal func refreshTokenExpirationDate() -> Date {

        return Date().addingTimeInterval(Double(refreshExpiresIn))
    }
    
    internal func remove() {
        
        KeychainWrapper.standard.removeObject(forKey: Constants.Keychain.KeycloakCredentials)
    }
    
    public func isExpired() -> Bool {
        
        return Date() > Date().addingTimeInterval(Double(refreshExpiresIn)) && Date() > Date().addingTimeInterval(Double(expiresIn))
    }

    private static func load() -> [String: Any]? {

        if let value = KeychainWrapper.standard.string(forKey: Constants.Keychain.KeycloakCredentials), let data = Data(base64Encoded: value) {
            do {
                return try JSONSerialization.jsonObject(with: data, options: .allowFragments) as? [String: Any]
            } catch let error {
                print("error converting to json: \(error)")
            }
        }

        return nil
    }
    
    private func save() {

        do {
            let data = try JSONSerialization.data(withJSONObject: props, options: .prettyPrinted)
            // Securley store the credentials
            guard KeychainWrapper.standard.set(data.base64EncodedString(), forKey: Constants.Keychain.KeycloakCredentials) else {
                fatalError("Unalbe to store auth credentials")
            }
        } catch let error {
            print("error converting to json: \(error)")
        }
    }
}
