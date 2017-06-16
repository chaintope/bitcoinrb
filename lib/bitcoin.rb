require 'bitcoin/version'

module Bitcoin

  autoload :ChainParams, 'bitcoin/chain_params'
  autoload :Logger, 'bitcoin/logger'

  @chain_param = :mainnet

  # set bitcoin network chain params
  def self.chain_params=(name)
    raise "chain params for #{name} is not defined." unless %i(mainnet testnet regtest).include?(name.to_sym)
    @current_chain = nil
    @chain_param = name.to_sym
  end

  # current bitcoin network chain params.
  def self.chain_params
    return @current_chain if @current_chain
    case @chain_param
      when :mainnet
        Bitcoin::ChainParams.mainnet
      when :testnet
        Bitcoin::ChainParams.testnet
      when :regtest
        Bitcoin::ChainParams.regtest
    end
  end

  # base dir path that store blockchain data and wallet data
  def self.base_dir
    "#{Dir.home}/.bitcoinrb"
  end

end
