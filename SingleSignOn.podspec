Pod::Spec.new do |s|
  s.name            = "SingleSignOn"
  s.version         = "1.0.4"
  s.summary         = "Library to interface with RedHat SSO"
  s.description     = "This pod contains various components to support authentication and credential managment"
  s.homepage        = "http://pathfinder.gov.bc.ca"
  s.license         = "Apache 2.0"
  s.author          = { "Jason C. Leach" => "jason.leach@fullboar.ca" }
  s.platform        = :ios, "9.0"
  s.source          = { :path => "./" }
  s.source_files    = "SingleSignOn/**/*.{swift}"
  s.resources       = 'SingleSignOn/**/*.{storyboard,xib,xcassets}'
  s.requires_arc    = true
  s.dependency      'SwiftKeychainWrapper', '~> 3.0.1'
  s.dependency      'Alamofire', '~> 4.7.3'
end
