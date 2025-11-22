require 'json'

package = JSON.parse(File.read(File.join(__dir__, 'package.json')))

Pod::Spec.new do |s|
  s.name         = "react-native-ecc-csr"
  s.version      = package['version']
  s.summary      = package['description']
  s.description  = <<-DESC
                  Native iOS implementation for generating ECC Certificate Signing Requests (CSR)
                  with support for P-256, P-384, and P-521 curves, X.509 extensions, and secure
                  keychain storage.
                   DESC
  s.homepage     = package['homepage']
  s.license      = package['license']
  s.authors      = package['author']
  s.platforms    = { :ios => "11.0" }
  s.source       = { :git => package['repository']['url'], :tag => "#{s.version}" }

  s.source_files = "ios/**/*.{h,m}"
  s.requires_arc = true

  s.dependency "React-Core"
end
