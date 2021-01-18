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
    attr_reader :bip49_pubkey_p2wpkh_p2sh_version
    attr_reader :bip49_privkey_p2wpkh_p2sh_version
    attr_reader :bip49_pubkey_p2wsh_p2sh_version
    attr_reader :bip49_privkey_p2wsh_p2sh_version
    attr_reader :bip84_pubkey_p2wpkh_version
    attr_reader :bip84_privkey_p2wpkh_version
    attr_reader :bip84_pubkey_p2wsh_version
    attr_reader :bip84_privkey_p2wsh_version
    attr_reader :default_port
    attr_reader :protocol_version
    attr_reader :retarget_interval
    attr_reader :retarget_time
    attr_reader :target_spacing
    attr_reader :max_money
    attr_reader :bip34_height
    attr_reader :proof_of_work_limit
    attr_reader :dns_seeds
    attr_reader :genesis
    attr_reader :bip44_coin_type

    attr_accessor :dust_relay_fee

    # mainnet genesis
    def self.mainnet
      init('mainnet')
    end

    # testnet genesis
    def self.testnet
      init('testnet')
    end

    # regtest genesis
    def self.regtest
      init('regtest')
    end

    # signet genesis
    def self.signet
      init('signet')
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

    def signet?
      network == 'signet'
    end

    def genesis_block
      header = Bitcoin::BlockHeader.new(
          genesis['version'], genesis['prev_hash'].rhex, genesis['merkle_root'].rhex,
          genesis['time'], genesis['bits'], genesis['nonce'])
      Bitcoin::Block.new(header)
    end

    def self.init(name)
      i = YAML.load(File.open("#{__dir__}/chainparams/#{name}.yml"))
      i.dust_relay_fee ||= Bitcoin::DUST_RELAY_TX_FEE
      i
    end

    private_class_method :init
  end

end