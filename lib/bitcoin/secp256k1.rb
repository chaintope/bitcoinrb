module Bitcoin

  module Secp256k1

    GROUP = ECDSA::Group::Secp256k1

    autoload :Ruby, 'bitcoin/secp256k1/ruby'
    autoload :Native, 'bitcoin/secp256k1/native'
    autoload :RFC6979, 'bitcoin/secp256k1/rfc6979'

  end

end
