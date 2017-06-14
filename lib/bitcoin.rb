require 'bitcoin/version'

module Bitcoin

  autoload :ChainParams, 'bitcoin/chain_params'
  autoload :Logger, 'bitcoin/logger'

  def self.base_dir
    "#{Dir.home}/.bitcoinrb"
  end

end
