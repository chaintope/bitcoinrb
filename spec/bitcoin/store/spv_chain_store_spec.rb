require 'spec_helper'
require 'tmpdir'
require 'fileutils'

describe Bitcoin::Store::SPVChainStore do

  TEST_DB_PATH = Dir.tmpdir + '/spv'

  before do
    FileUtils.rm_r(TEST_DB_PATH) if Dir.exist?(TEST_DB_PATH)
  end

  subject {
    Bitcoin::Store::SPVChainStore.new(Bitcoin::Store::DB::LevelDB.new(TEST_DB_PATH))
  }

  it 'should store data' do
    genesis = subject.latest_block
    expect(genesis.height).to eq(0)
    expect(genesis.header).to eq(Bitcoin.chain_params.genesis_block.header)

    next_header = Bitcoin::BlockHeader.parse_from_payload('0100000043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000bac8b0fa927c0ac8234287e33c5f74d38d354820e24756ad709d7038fc5f31f020e7494dffff001d03e4b672'.htb)
    next_entry = genesis.build_next_block(next_header)
    subject.save_block(next_entry)

    block = subject.latest_block
    expect(block.height).to eq(1)
    expect(block.header).to eq(next_header)
  end

end