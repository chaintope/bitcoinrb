require 'spec_helper'
require 'tmpdir'
require 'fileutils'

describe Bitcoin::Store::SPVChain do

  let (:chain) { create_test_chain }
  after { chain.db.close }

  describe '#find_entry_by_hash' do
    subject { chain.find_entry_by_hash(target) }

    let(:next_header) do
      Bitcoin::BlockHeader.parse_from_payload(
        '0100000043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea3309' \
        '00000000bac8b0fa927c0ac8234287e33c5f74d38d354820e24756ad709d7038' \
        'fc5f31f020e7494dffff001d03e4b672'.htb
      )
    end
    let(:target) {'06128e87be8b1b4dea47a7247d5528d2702c96826c7a648497e773b800000000' }

    before do
      chain.append_header(next_header)
    end

    it 'return correct ChainEntry' do
      expect(subject.header).to eq next_header
      expect(subject.height).to eq 1
    end

    context 'header is not stored' do
      let(:target) {'0000000000000000000000000000000000000000000000000000000000000000' }

      it { expect(subject).to be_nil }
    end
  end

  describe '#append_header' do
    subject { chain }

    context 'correct header' do
      it 'should store data' do
        genesis = subject.latest_block
        expect(genesis.height).to eq(0)
        expect(genesis.header).to eq(Bitcoin.chain_params.genesis_block.header)
        expect(subject.next_hash('43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000')).to be nil

        next_header = Bitcoin::BlockHeader.parse_from_payload('0100000043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000bac8b0fa927c0ac8234287e33c5f74d38d354820e24756ad709d7038fc5f31f020e7494dffff001d03e4b672'.htb)
        subject.append_header(next_header)

        block = subject.latest_block
        expect(block.height).to eq(1)
        expect(block.header).to eq(next_header)
        expect(subject.next_hash('43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000')).to eq('06128e87be8b1b4dea47a7247d5528d2702c96826c7a648497e773b800000000')
      end
    end

    context 'invalid header' do
      it 'should raise error' do
        # pow is invalid
        next_header = Bitcoin::BlockHeader.parse_from_payload('0100000043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000bac8b0fa927c0ac8234287e33c5f74d38d354820e24756ad709d7038fc5f31f020e7494dffff001d03e4b672'.htb)
        next_header.nonce = 1
        expect{subject.append_header(next_header)}.to raise_error(StandardError)

        # previous hash mismatch
        next_header = Bitcoin::BlockHeader.parse_from_payload('0100000006128e87be8b1b4dea47a7247d5528d2702c96826c7a648497e773b800000000e241352e3bec0a95a6217e10c3abb54adfa05abb12c126695595580fb92e222032e7494dffff001d00d23534'.htb)
        expect{subject.append_header(next_header)}.to raise_error(StandardError)
      end
    end

    context 'duplicate header' do
      it 'should not raise error' do
        # add block 1, 2
        header1 = Bitcoin::BlockHeader.parse_from_payload('0100000043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000bac8b0fa927c0ac8234287e33c5f74d38d354820e24756ad709d7038fc5f31f020e7494dffff001d03e4b672'.htb)
        header2 = Bitcoin::BlockHeader.parse_from_payload('0100000006128e87be8b1b4dea47a7247d5528d2702c96826c7a648497e773b800000000e241352e3bec0a95a6217e10c3abb54adfa05abb12c126695595580fb92e222032e7494dffff001d00d23534'.htb)
        subject.append_header(header1)
        subject.append_header(header2)

        # add duplicate header 1
        expect{subject.append_header(header1)}.not_to raise_error
        expect(subject.latest_block.header).to eq(header2)
      end
    end
  end

  describe '#mtp' do
    subject { chain }

    it 'should return median time' do
      Bitcoin.chain_params = :mainnet
      # bitcoin mainnet
      headers = [
        # time = 1231469665
        Bitcoin::BlockHeader.parse_from_payload('010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299'.htb),
        # time = 1231469744
        Bitcoin::BlockHeader.parse_from_payload('010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd61'.htb),
        # time = 1231470173
        Bitcoin::BlockHeader.parse_from_payload('01000000bddd99ccfda39da1b108ce1a5d70038d0a967bacb68b6b63065f626a0000000044f672226090d85db9a9f2fbfe5f0f9609b387af7be5b7fbb7a1767c831c9e995dbe6649ffff001d05e0ed6d'.htb),
        # time = 1231470988
        Bitcoin::BlockHeader.parse_from_payload('010000004944469562ae1c2c74d9a535e00b6f3e40ffbad4f2fda3895501b582000000007a06ea98cd40ba2e3288262b28638cec5337c1456aaf5eedc8e9e5a20f062bdf8cc16649ffff001d2bfee0a9'.htb),
        # time = 1231471428
        Bitcoin::BlockHeader.parse_from_payload('0100000085144a84488ea88d221c8bd6c059da090e88f8a2c99690ee55dbba4e00000000e11c48fecdd9e72510ca84f023370c9a38bf91ac5cae88019bee94d24528526344c36649ffff001d1d03e477'.htb),
        # time = 1231471789
        Bitcoin::BlockHeader.parse_from_payload('01000000fc33f596f822a0a1951ffdbf2a897b095636ad871707bf5d3162729b00000000379dfb96a5ea8c81700ea4ac6b97ae9a9312b2d4301a29580e924ee6761a2520adc46649ffff001d189c4c97'.htb),
        # time = 1231472369
        Bitcoin::BlockHeader.parse_from_payload('010000008d778fdc15a2d3fb76b7122a3b5582bea4f21f5a0c693537e7a03130000000003f674005103b42f984169c7d008370967e91920a6a5d64fd51282f75bc73a68af1c66649ffff001d39a59c86'.htb),
        # time = 1231472743
        Bitcoin::BlockHeader.parse_from_payload('010000004494c8cf4154bdcc0720cd4a59d9c9b285e4b146d45f061d2b6c967100000000e3855ed886605b6d4a99d5fa2ef2e9b0b164e63df3c4136bebf2d0dac0f1f7a667c86649ffff001d1c4b5666'.htb),
        # time = 1231473279
        Bitcoin::BlockHeader.parse_from_payload('01000000c60ddef1b7618ca2348a46e868afc26e3efc68226c78aa47f8488c4000000000c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd37047fca6649ffff001d28404f53'.htb),
        # time = 1231473952
        Bitcoin::BlockHeader.parse_from_payload('010000000508085c47cc849eb80ea905cc7800a3be674ffc57263cf210c59d8d00000000112ba175a1e04b14ba9e7ea5f76ab640affeef5ec98173ac9799a852fa39add320cd6649ffff001d1e2de565'.htb),
        # time = 1231474360
        Bitcoin::BlockHeader.parse_from_payload('01000000e915d9a478e3adf3186c07c61a22228b10fd87df343c92782ecc052c000000006e06373c80de397406dc3d19c90d71d230058d28293614ea58d6a57f8f5d32f8b8ce6649ffff001d173807f8'.htb),
      ]
      headers.each { |h| subject.append_header(h) }
      expect(subject.mtp('7330d7adf261c69891e6ab08367d957e74d4044bc5d9cd06d656be9700000000')).to eq 1_231_471_789
    end

    context 'block height is less than Bitcoin::MEDIAN_TIME_SPAN(11)' do
      it do
        Bitcoin.chain_params = :mainnet
        # bitcoin mainnet
        headers = [
          # time = 1231469665
          Bitcoin::BlockHeader.parse_from_payload('010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299'.htb),
          # time = 1231469744
          Bitcoin::BlockHeader.parse_from_payload('010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd61'.htb),
          # time = 1231470173
          Bitcoin::BlockHeader.parse_from_payload('01000000bddd99ccfda39da1b108ce1a5d70038d0a967bacb68b6b63065f626a0000000044f672226090d85db9a9f2fbfe5f0f9609b387af7be5b7fbb7a1767c831c9e995dbe6649ffff001d05e0ed6d'.htb),
          # time = 1231470988
          Bitcoin::BlockHeader.parse_from_payload('010000004944469562ae1c2c74d9a535e00b6f3e40ffbad4f2fda3895501b582000000007a06ea98cd40ba2e3288262b28638cec5337c1456aaf5eedc8e9e5a20f062bdf8cc16649ffff001d2bfee0a9'.htb),
          # time = 1231471428
          Bitcoin::BlockHeader.parse_from_payload('0100000085144a84488ea88d221c8bd6c059da090e88f8a2c99690ee55dbba4e00000000e11c48fecdd9e72510ca84f023370c9a38bf91ac5cae88019bee94d24528526344c36649ffff001d1d03e477'.htb),
          # time = 1231471789
          Bitcoin::BlockHeader.parse_from_payload('01000000fc33f596f822a0a1951ffdbf2a897b095636ad871707bf5d3162729b00000000379dfb96a5ea8c81700ea4ac6b97ae9a9312b2d4301a29580e924ee6761a2520adc46649ffff001d189c4c97'.htb),
          # time = 1231472369
          Bitcoin::BlockHeader.parse_from_payload('010000008d778fdc15a2d3fb76b7122a3b5582bea4f21f5a0c693537e7a03130000000003f674005103b42f984169c7d008370967e91920a6a5d64fd51282f75bc73a68af1c66649ffff001d39a59c86'.htb),
          # time = 1231472743
          Bitcoin::BlockHeader.parse_from_payload('010000004494c8cf4154bdcc0720cd4a59d9c9b285e4b146d45f061d2b6c967100000000e3855ed886605b6d4a99d5fa2ef2e9b0b164e63df3c4136bebf2d0dac0f1f7a667c86649ffff001d1c4b5666'.htb),
          # time = 1231473279
          Bitcoin::BlockHeader.parse_from_payload('01000000c60ddef1b7618ca2348a46e868afc26e3efc68226c78aa47f8488c4000000000c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd37047fca6649ffff001d28404f53'.htb),
        ]
        headers.each { |h| subject.append_header(h) }
        expect(subject.mtp('0508085c47cc849eb80ea905cc7800a3be674ffc57263cf210c59d8d00000000')).to eq 1_231_471_428
      end
    end
  end
end
