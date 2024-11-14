# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'bitcoin/version'

Gem::Specification.new do |spec|

  spec.name          = "bitcoinrb"
  spec.version       = Bitcoin::VERSION
  spec.authors       = ["azuchi"]
  spec.email         = ["azuchi@chaintope.com"]

  spec.summary       = %q{The implementation of Bitcoin Protocol for Ruby.}
  spec.description   = %q{The implementation of Bitcoin Protocol for Ruby.}
  spec.homepage      = 'https://github.com/chaintope/bitcoinrb'
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_runtime_dependency 'ecdsa_ext', '~> 0.5.1'
  spec.add_runtime_dependency 'eventmachine'
  spec.add_runtime_dependency 'murmurhash3', '~> 0.1.7'
  spec.add_runtime_dependency 'bech32', '>= 1.3.0'
  spec.add_runtime_dependency 'daemon-spawn'
  spec.add_runtime_dependency 'thor'
  spec.add_runtime_dependency 'ffi'
  spec.add_runtime_dependency 'leb128', '~> 1.0.0'
  spec.add_runtime_dependency 'eventmachine_httpserver'
  spec.add_runtime_dependency 'iniparse'
  spec.add_runtime_dependency 'siphash'
  spec.add_runtime_dependency 'json_pure', '>= 2.3.1', '< 2.8.0'
  spec.add_runtime_dependency 'bip-schnorr', '>= 0.7.0'
  spec.add_runtime_dependency 'base32', '>= 0.3.4'
  spec.add_runtime_dependency 'base64', '~> 0.2.0'
  spec.add_runtime_dependency 'observer', '~> 0.1.2'
  spec.add_runtime_dependency 'secp256k1rb', '0.1.1'
end
