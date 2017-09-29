require 'spec_helper'

describe Bitcoin::BlockHeader do

  describe 'parse from payload' do
    subject {Bitcoin::BlockHeader.parse_from_payload('00000020f29ae31fe472fea5a9812cd8bd9d73c7e4491ee62fbaf9b1be20000000000000e4e24580186a17432dee5ada29678f3f5e6b51a451f3b8d09917a2de11dba12d11bd48590bd6001bcd3c87cb'.htb)}
    it 'should be parsed' do
      expect(subject.hash).to eq('000000000000a7c25a2032d97800c509e4d6ccd633212c5956a52c58d8cef11d')
      expect(subject.time).to eq(1497939217)
      expect(subject.nonce).to eq(3414637773)
      expect(subject.prev_hash).to eq('00000000000020beb1f9ba2fe61e49e4c7739dbdd82c81a9a5fe72e41fe39af2')
      expect(subject.merkle_root).to eq('2da1db11dea21799d0b8f351a4516b5e3f8f6729da5aee2d43176a188045e2e4')
      expect(subject.bits).to eq(453039627)
    end
  end

  describe 'to_payload' do
    subject {
      Bitcoin::BlockHeader.parse_from_payload('00000020f29ae31fe472fea5a9812cd8bd9d73c7e4491ee62fbaf9b1be20000000000000e4e24580186a17432dee5ada29678f3f5e6b51a451f3b8d09917a2de11dba12d11bd48590bd6001bcd3c87cb'.htb)
    }
    it 'should be generate payload' do
      expect(subject.to_payload.bth).to eq('00000020f29ae31fe472fea5a9812cd8bd9d73c7e4491ee62fbaf9b1be20000000000000e4e24580186a17432dee5ada29678f3f5e6b51a451f3b8d09917a2de11dba12d11bd48590bd6001bcd3c87cb')
    end
  end

  describe '#bits_to_target' do
    it 'return difficulty target' do
      header = Bitcoin::BlockHeader.parse_from_payload('00000020f29ae31fe472fea5a9812cd8bd9d73c7e4491ee62fbaf9b1be20000000000000e4e24580186a17432dee5ada29678f3f5e6b51a451f3b8d09917a2de11dba12d11bd48590bd6001bcd3c87cb'.htb)
      puts header.bits
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
