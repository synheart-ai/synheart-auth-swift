Pod::Spec.new do |s|
  s.name             = 'SynheartAuth'
  s.version          = '0.1.0'
  s.summary          = 'Synheart device authentication SDK for iOS.'
  s.description      = <<~DESC
    Native iOS SDK for Synheart device authentication: Secure Enclave P-256
    key management, Keychain-backed storage, App Attest binding, and signed
    request headers. Consumed both as a SwiftPM package and as a CocoaPod
    (the Flutter plugin `synheart_auth` depends on this pod).
  DESC
  s.homepage         = 'https://github.com/synheart-ai/synheart-auth-swift'
  s.license          = { :type => 'Apache-2.0', :file => 'LICENSE' }
  s.author           = 'Synheart'
  s.source           = { :git => 'https://github.com/synheart-ai/synheart-auth-swift.git', :tag => s.version.to_s }
  s.source_files     = 'Sources/SynheartAuth/**/*.swift'
  s.frameworks       = 'Security', 'DeviceCheck', 'CryptoKit'
  s.ios.deployment_target = '15.0'
  s.osx.deployment_target = '13.0'
  s.swift_version    = '5.9'
end
