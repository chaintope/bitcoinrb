$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)
require 'bitcoin'
require 'logger'
require 'timecop'
require 'webmock/rspec'
require 'parallel'
require 'csv'

def use_secp256k1
  host_os = RbConfig::CONFIG['host_os']
  case host_os
  when /linux/
    ENV['SECP256K1_LIB_PATH'] = ENV['TEST_LIBSECP256K1_PATH'] || File.expand_path('lib/libsecp256k1.so', File.dirname(__FILE__))
  else
    if ENV['LIBSECP_PATH']
      ENV['SECP256K1_LIB_PATH'] = ENV['TEST_LIBSECP256K1_PATH']
    else
      raise "To run this test, environment variable \"TEST_LIBSECP256K1_PATH\" must specify the path to a valid libsecp256k1 library."
    end
  end
end

def use_ecdsa_gem
  ENV['SECP256K1_LIB_PATH'] = nil
end

def fixture_file(relative_path)
  file = File.read(fixture_path(relative_path))
  JSON.parse(file)
end

def fixture_path(relative_path)
  File.join(File.dirname(__FILE__), 'fixtures', relative_path)
end

def read_csv(relative_path)
  CSV.read(File.join(File.dirname(__FILE__), 'fixtures', relative_path), headers: true)
end

def load_block(hash)
  File.read(File.join(File.dirname(__FILE__), 'fixtures', "block/#{hash}"))
end

def load_payment(file_name)
  File.read(File.join(File.dirname(__FILE__), 'fixtures', "payments/#{file_name}"))
end

TEST_DB_PATH = "#{Dir.tmpdir}/#{ENV['TEST_ENV_NUMBER']}/spv"

def create_test_chain
  FileUtils.rm_r(TEST_DB_PATH) if Dir.exist?(TEST_DB_PATH)
  Bitcoin::Store::SPVChain.new(Bitcoin::Store::DB::LevelDB.new(TEST_DB_PATH))
end

TEST_WALLET_PATH = "#{Dir.tmpdir}/#{ENV['TEST_ENV_NUMBER']}/wallet-test/"

def test_wallet_path(wallet_id = 1)
  "#{TEST_WALLET_PATH}wallet#{wallet_id}/"
end

def create_test_wallet(wallet_id = 1, purpose = Bitcoin::Wallet::Account::PURPOSE_TYPE[:native_segwit])
  path = test_wallet_path(wallet_id)
  FileUtils.rm_r(path) if Dir.exist?(path)
  Bitcoin::Wallet::Base.create(wallet_id, TEST_WALLET_PATH, purpose)
end

def test_master_key
  words = %w(abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about)
  Bitcoin::Wallet::MasterKey.recover_from_words(words)
end

TEST_UTXO_DB_PATH = Dir.tmpdir + '/db/test_utxo'

def create_test_utxo_db()
  FileUtils.rm_r(TEST_UTXO_DB_PATH) if Dir.exist?(TEST_UTXO_DB_PATH)
  Bitcoin::Store::UtxoDB.new(TEST_UTXO_DB_PATH)
end

module Bitcoin
  autoload :TestScriptParser, 'bitcoin/script/test_script_parser'
end

RSpec::Matchers.define :custom_object do |clazz, properties|
  match do |actual|
    return false unless actual.is_a?(clazz)
    properties.each do |key, value|
      return false unless actual.send(key) == value
    end
    true
  end
end

use_secp256k1

RSpec.configure do |config|
  config.before(:each) do |example|
    if example.metadata[:network]
      Bitcoin.chain_params = example.metadata[:network]
    else
      Bitcoin.chain_params = :testnet
    end
    if example.metadata[:use_secp256k1]
      use_secp256k1
    else
      use_ecdsa_gem
    end
  end
end

RSpec::Matchers.define :have_same_elements_as_any_of do |expected_arrays|
  match do |actual|
    expected_arrays.any? { |expected| actual.to_set == expected.to_set }
  end

  failure_message do |actual|
    "expected #{actual} to have the same elements as any of: #{expected_arrays.inspect}"
  end
end
