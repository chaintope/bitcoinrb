require 'yaml'

module Bitcoin

  # Network parameter class
  class ChainParams

    attr_reader :network
    attr_reader :magic_head
    attr_reader :message_magic
    attr_reader :address_version
    attr_reader :p2sh_version
    attr_reader :bech32_hrp
    attr_reader :privkey_version
    attr_reader :extended_privkey_version
    attr_reader :extended_pubkey_version
    attr_reader :default_port
    attr_reader :protocol_version
    attr_reader :retarget_interval
    attr_reader :retarget_time
    attr_reader :target_spacing
    attr_reader :max_money
    attr_reader :bip34_height
    attr_reader :genesis_hash
    attr_reader :proof_of_work_limit
    attr_reader :dns_seeds

    # mainnet params
    def self.mainnet
      YAML.load(File.open("#{__dir__}/chainparams/mainnet.yml"))
    end

    # testnet params
    def self.testnet
      YAML.load(File.open("#{__dir__}/chainparams/testnet.yml"))
    end

    # regtest params
    def self.regtest
      YAML.load(File.open("#{__dir__}/chainparams/regtest.yml"))
    end

    def mainnet?
      network == 'mainnet'
    end

    def testnet?
      network == 'testnet'
    end

    def regtest?
      network == 'regtest'
    end

  end

end