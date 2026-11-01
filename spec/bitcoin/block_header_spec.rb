require 'spec_helper'

describe Bitcoin::BlockHeader do

  describe 'parse from payload' do
    subject {Bitcoin::BlockHeader.parse_from_payload('00000020f29ae31fe472fea5a9812cd8bd9d73c7e4491ee62fbaf9b1be20000000000000e4e24580186a17432dee5ada29678f3f5e6b51a451f3b8d09917a2de11dba12d11bd48590bd6001bcd3c87cb'.htb)}
    it 'should be parsed' do
      expect(subject.block_hash).to eq('1df1ced8582ca556592c2133d6ccd6e409c50078d932205ac2a7000000000000')
      expect(subject.time).to eq(1497939217)
      expect(subject.nonce).to eq(3414637773)
      expect(subject.prev_hash).to eq('f29ae31fe472fea5a9812cd8bd9d73c7e4491ee62fbaf9b1be20000000000000')
      expect(subject.merkle_root).to eq('e4e24580186a17432dee5ada29678f3f5e6b51a451f3b8d09917a2de11dba12d')
      expect(subject.bits).to eq(453039627)
    end
  end

  describe 'to_payload' do
    subject {
      Bitcoin::BlockHeader.parse_from_payload('00000020f29ae31fe472fea5a9812cd8bd9d73c7e4491ee62fbaf9b1be20000000000000e4e24580186a17432dee5ada29678f3f5e6b51a451f3b8d09917a2de11dba12d11bd48590bd6001bcd3c87cb'.htb)
    }
    it 'should be generate payload' do
      expect(subject.to_hex).to eq('00000020f29ae31fe472fea5a9812cd8bd9d73c7e4491ee62fbaf9b1be20000000000000e4e24580186a17432dee5ada29678f3f5e6b51a451f3b8d09917a2de11dba12d11bd48590bd6001bcd3c87cb')
    end
  end

  describe '#bits_to_target' do
    it 'return difficulty target' do
      header = Bitcoin::BlockHeader.parse_from_payload('00000020f29ae31fe472fea5a9812cd8bd9d73c7e4491ee62fbaf9b1be20000000000000e4e24580186a17432dee5ada29678f3f5e6b51a451f3b8d09917a2de11dba12d11bd48590bd6001bcd3c87cb'.htb)
      expect(header.difficulty_target).to eq(0x000000000000d60b000000000000000000000000000000000000000000000000)

      header.bits = 0x1d00ffff
      expect(header.difficulty_target).to eq(0x00000000ffff0000000000000000000000000000000000000000000000000000)

      header.bits = 0x1b0ffff0
      expect(header.difficulty_target).to eq(0x00000000000ffff0000000000000000000000000000000000000000000000000)

      header.bits = 0x03000000
      expect(header.difficulty_target).to eq(0x00)

      header.bits = 0x1b00b5ac
      expect(header.difficulty_target).to eq(0x000000000000b5ac000000000000000000000000000000000000000000000000)

      header.bits = 0x1c654657
      expect(header.difficulty_target).to eq(0x0000000065465700000000000000000000000000000000000000000000000000)

      # An exponent below 3 shifts the mantissa right, dropping the low bytes as Bitcoin Core's SetCompact does.
      header.bits = 0x0200ffff
      expect(header.difficulty_target).to eq(0xff)
      header.bits = 0x01003456
      expect(header.difficulty_target).to eq(0)
      # The sign bit makes the target negative.
      header.bits = 0x1d80ffff
      expect(header.difficulty_target).to eq(-0x00000000ffff0000000000000000000000000000000000000000000000000000)
      expect(header.work).to eq(0)
      # A target which does not fit in 256 bits.
      expect(Bitcoin::BlockHeader.compact_overflow?(0xff7fffff)).to be true
      expect(Bitcoin::BlockHeader.compact_overflow?(0x23010000)).to be true
      expect(Bitcoin::BlockHeader.compact_overflow?(0x210100ff)).to be true
      expect(Bitcoin::BlockHeader.compact_overflow?(0x220100ff)).to be true
      expect(Bitcoin::BlockHeader.compact_overflow?(0x220000ff)).to be false
      expect(Bitcoin::BlockHeader.compact_overflow?(0xff000000)).to be false
      header.bits = 0xff7fffff
      expect(header.work).to eq(0)
    end
  end

  describe '#valid_pow?' do
    subject {
      payload = load_block('0000000000343e7e31a6233667fd6ed5288d60ed7e894ae5d53beb0dffc89170').htb
      Bitcoin::Message::Block.parse_from_payload(payload).header
    }
    it 'evaluate pow' do
      expect(subject.valid_pow?).to be true
      subject.bits = 496604799
      expect(subject.valid_pow?).to be false
    end

    # The cases of Bitcoin Core's pow_tests, with the hash of the header stubbed.
    context 'the target is out of range', network: :mainnet do
      let(:pow_limit) { 0x00000000ffff0000000000000000000000000000000000000000000000000000 }
      let(:header) { Bitcoin::BlockHeader.new(1, '00' * 32, '00' * 32, 0, 0x1d00ffff, 0) }

      def pow_with(bits, hash)
        header.bits = bits
        allow(header).to receive(:block_id).and_return('%064x' % hash)
        header.valid_pow?
      end

      it 'should reject a negative, zero, overflowing or too easy target' do
        expect(pow_with(0x1d80ffff, 1)).to be false # negative target
        expect(pow_with(0x00000000, 0)).to be false # zero target
        expect(pow_with(0xff7fffff, 1)).to be false # overflow target
        expect(pow_with(0x1d01fffe, 1)).to be false # too easy target: twice the proof of work limit
        expect(pow_with(0x1d00ffff, 1)).to be true  # the proof of work limit itself
      end

      it 'should accept a hash equal to the target and reject a greater one' do
        expect(pow_with(0x1d00ffff, pow_limit)).to be true
        expect(pow_with(0x1d00ffff, pow_limit + 1)).to be false
        expect(pow_with(0x1d00ffff, pow_limit * 2)).to be false
      end

      it 'should apply the proof of work limit of the current chain' do
        Bitcoin.chain_params = :regtest
        expect(pow_with(0x207fffff, 1)).to be true
        expect(pow_with(0x1d01fffe, 1)).to be true # easier than mainnet's limit, within regtest's
        expect(pow_with(0x20800000, 1)).to be false # negative
        Bitcoin.chain_params = :mainnet
      end
    end
  end

  describe '#valid_timestamp?' do
    subject {
      Bitcoin::BlockHeader.parse_from_payload('00000020f29ae31fe472fea5a9812cd8bd9d73c7e4491ee62fbaf9b1be20000000000000e4e24580186a17432dee5ada29678f3f5e6b51a451f3b8d09917a2de11dba12d11bd48590bd6001bcd3c87cb'.htb)
    }

    before {
      Timecop.freeze(Time.utc(2017, 9, 22, 15, 13, 25))
    }

    context 'too future' do
      it 'should be false' do
        subject.time = Time.utc(2017, 9, 22, 17, 13, 26).to_i
        expect(subject.valid_timestamp?).to be false
      end
    end

    context 'recent time' do
      it 'should be true' do
        subject.time = Time.utc(2017, 9, 22, 17, 13, 25).to_i
        expect(subject.valid_timestamp?).to be true
      end
    end

    after {
      Timecop.return
    }
  end

  describe '#work' do
    subject {
      Bitcoin::BlockHeader.parse_from_payload('000000207d7a225081665d83116ce0f1c3eaf10d26ee917d03fbd7aad6895f9800000000b5c7027f92cbca51da5b758af41b7cc23d43a456d7abd4f54357b492c233347294dccd59ffff001d00ff2046'.htb)
    }
    it 'should be calculate' do
      expect(subject.work).to eq(4295032833)
    end
  end

end
