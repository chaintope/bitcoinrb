require 'spec_helper'

describe Bitcoin do

  it 'has a version number' do
    expect(Bitcoin::VERSION).not_to be nil
  end

  it 'change bitcoin network' do
    Bitcoin.chain_params = :mainnet
    expect(Bitcoin.chain_params.network).to eq('mainnet')
    Bitcoin.chain_params = :testnet
    expect(Bitcoin.chain_params.network).to eq('testnet')
    Bitcoin.chain_params = :regtest
    expect(Bitcoin.chain_params.network).to eq('regtest')
    expect { Bitcoin.chain_params = :hoge }.to raise_error(RuntimeError)
  end

end
