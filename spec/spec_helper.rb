$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)
require 'bitcoin'

RSpec.configure do |config|
  config.before(:each) do |example|
    if example.metadata[:network]
      Bitcoin.chain_params = example.metadata[:network]
    else
      Bitcoin.chain_params = :testnet
    end
    if example.metadata[:use_secp256k1]
      ENV['SECP256K1_LIB_PATH'] = File.expand_path('lib/libsecp256k1.so', File.dirname(__FILE__))
    else
      ENV['SECP256K1_LIB_PATH'] = nil
    end
  end
end

def fixture_file(relative_path)
  file = File.read(File.join(File.dirname(__FILE__), 'fixtures', relative_path))
  JSON.parse(file)
end

module Bitcoin
  autoload :TestScriptParser, 'bitcoin/script/test_script_parser'
end