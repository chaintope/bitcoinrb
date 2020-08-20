module Bitcoin
  module Errors

    module Messages

      INVALID_PUBLIC_KEY = 'Invalid public key.'
      INVALID_BIP32_PRIV_PREFIX = 'Invalid BIP32 private key prefix. prefix must be 0x00.'
      INVALID_BIP32_FINGERPRINT = 'Invalid parent fingerprint.'
      INVALID_BIP32_ZERO_INDEX = 'Invalid index. Depth 0 must have 0 index.'
      INVALID_BIP32_ZERO_DEPTH = 'Invalid depth. Master key must have 0 depth.'
      INVALID_BIP32_VERSION = 'An unsupported version byte was specified.'

      INVALID_PRIV_KEY = 'Private key is not in range [1..n-1].'
      INVALID_CHECKSUM = 'Invalid checksum.'

    end

  end
end