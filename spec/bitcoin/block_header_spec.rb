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

end