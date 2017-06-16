$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)
require 'bitcoin'

RSpec.configure do |config|
  config.before(:each) do |example|
    if example.metadata[:network]
      Bitcoin.chain_params = example.metadata[:network]
    else
      Bitcoin.chain_params = :testnet
    end
  end
end