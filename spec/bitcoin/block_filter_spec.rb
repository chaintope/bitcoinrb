require 'spec_helper'

describe Bitcoin::BlockFilter do

  describe 'Test Vector blockfilters.json' do
    filter_json = fixture_file('blockfilters.json').select{|j|j.size > 1}
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

  describe '#match?' do
    it 'should generate filter' do
      included = []
      # P2PK
      included[0] = Bitcoin::Script.parse_from_payload('00ac'.htb)
      # p2PKH
      included[1] = Bitcoin::Script.parse_from_payload('76a9011488ac'.htb)
      # 1-of-1 multisig
      included[2] = Bitcoin::Script.parse_from_payload('5102212151ae'.htb)
      included[3] = Bitcoin::Script.parse_from_payload('0003202020'.htb)
      included[4] = Bitcoin::Script.parse_from_payload('54935887'.htb)

      excluded = []
      # op_return
      excluded[0] = Bitcoin::Script.parse_from_payload('6a0428282828'.htb)
      # not related P2PK
      excluded[1] = Bitcoin::Script.parse_from_payload('052121212121ac'.htb)
      # empty
      excluded[2] = Bitcoin::Script.new

      tx1 = Bitcoin::Tx.new
      tx1.out << Bitcoin::TxOut.new(value: 100, script_pubkey: included[0])
      tx1.out << Bitcoin::TxOut.new(value: 200, script_pubkey: included[1])

      tx2 = Bitcoin::Tx.new
      tx2.out << Bitcoin::TxOut.new(value: 300, script_pubkey: included[2])
      tx2.out << Bitcoin::TxOut.new(script_pubkey: excluded[0])
      tx2.out << Bitcoin::TxOut.new(value: 400, script_pubkey: excluded[2])

      header = Bitcoin::BlockHeader.new(0, '00' * 32, '00' * 32, 0, 0, 0)
      block = Bitcoin::Block.new(header, [tx1, tx2])

      prev_out_scripts = []
      prev_out_scripts << included[3]
      prev_out_scripts << included[4]
      prev_out_scripts << excluded[2]

      block_filter = Bitcoin::BlockFilter.build_from_block(Bitcoin::BlockFilter::TYPE[:basic], block, prev_out_scripts)
      filter = block_filter.filter
      expect(filter.encoded).to eq('05812be2f176a9b8066fa3b1264f')

      included.each do |i|
        expect(filter.match?(i.to_payload)).to be true
      end

      excluded.each do |e|
        expect(filter.match?(e.to_payload)).to be false
      end
    end
  end

  describe '#decode' do
    subject {
      block_hash = '6e33538c0c3526e3590ebff9710dbc5d5472fed28e63d94bac8dc20fa7000000'
      encoded_filter = '0c79dd114255fdef1542cd3f2495e0f9346b4fc32a154639f375e0691ce5a36d'
      Bitcoin::BlockFilter.decode(Bitcoin::BlockFilter::TYPE[:basic], block_hash, encoded_filter)
    }
    it 'should decode encoded filter.' do
      expect(subject.filter.encoded).to eq('0c79dd114255fdef1542cd3f2495e0f9346b4fc32a154639f375e0691ce5a36d')
      target = '00141ed6f4590e7088dbebdf66b7072e87ab9c29b0c0'.htb
      expect(subject.filter.match?(target)).to be true
      target = '00141ed6f4590e7088dbebdf66b7072e87ab9c29b0c1'.htb
      expect(subject.filter.match?(target)).to be false
    end
  end
end