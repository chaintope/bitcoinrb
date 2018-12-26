require 'spec_helper'

describe Bitcoin::BlockFilter do

  describe 'Test Vector testnet-19.json' do
    filter_json = fixture_file('bip158/testnet-19.json').select{|j|j.size > 1}
    # Block Height,Block Hash,Block,[Prev Output Scripts for Block],Previous Basic Header,Basic Filter,Basic Header,Notes
    filter_json.each do |height, block_hash, raw_block, prev_out_scripts, prev_basic_header, basic_filter, basic_header, note|
      it "should validate #{note} block" do
        scripts = prev_out_scripts.map{|script|Bitcoin::Script.parse_from_payload(script.htb)}
        block = Bitcoin::Block.parse_from_payload(raw_block.htb)
        block_filter = Bitcoin::BlockFilter.build_from_block(Bitcoin::BlockFilter::TYPE[:basic], block, scripts)
        expect(block_filter.encoded_filter).to eq(basic_filter)
        expect(block_filter.header(prev_basic_header.htb.reverse.bth).htb.reverse.bth).to eq(basic_header)
        expect(block_filter.block_hash).to eq(block_hash.htb.reverse.bth)
      end
    end
  end

end