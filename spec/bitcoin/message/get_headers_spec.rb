require 'spec_helper'

describe Bitcoin::Message::GetHeaders do

  describe 'to_pkt' do
    subject {
      blocks = [
          'd18af7986e37cce50bd1840a4355b76c3127847538f598ca3c11050000000000',
          '16fcb7157eb73f293f39a5f999beae35638fd760531968e5ba06010000000000',
          'b243161b0c4df323ef0a7db26b1d5af1312c76b0cb1dd804e634000000000000'
      ]
      Bitcoin::Message::GetHeaders.new(70015, blocks).to_pkt
    }
    it do
      expect(subject).to eq('0b11090767657468656164657273000085000000aa956d887f11010003d18af7986e37cce50bd1840a4355b76c3127847538f598ca3c1105000000000016fcb7157eb73f293f39a5f999beae35638fd760531968e5ba06010000000000b243161b0c4df323ef0a7db26b1d5af1312c76b0cb1dd804e6340000000000000000000000000000000000000000000000000000000000000000000000000000'.htb)
    end
  end

  describe 'parse from payload' do
    subject{
      Bitcoin::Message::GetHeaders.parse_from_payload('7f11010003d18af7986e37cce50bd1840a4355b76c3127847538f598ca3c1105000000000016fcb7157eb73f293f39a5f999beae35638fd760531968e5ba06010000000000b243161b0c4df323ef0a7db26b1d5af1312c76b0cb1dd804e6340000000000000000000000000000000000000000000000000000000000000000000000000000'.htb)
    }
    it do
      expect(subject.version).to eq(70015)
      expect(subject.hashes.length).to eq(3)
      expect(subject.hashes[0]).to eq('d18af7986e37cce50bd1840a4355b76c3127847538f598ca3c11050000000000')
      expect(subject.hashes[1]).to eq('16fcb7157eb73f293f39a5f999beae35638fd760531968e5ba06010000000000')
      expect(subject.hashes[2]).to eq('b243161b0c4df323ef0a7db26b1d5af1312c76b0cb1dd804e634000000000000')
      expect(subject.stop_hash).to eq('0000000000000000000000000000000000000000000000000000000000000000')
    end
  end


  describe 'locator size' do
    it 'should accept 101 hashes and reject 102, as Bitcoin Core does' do
      hashes = Array.new(101) { 'aa' * 32 }
      expect(Bitcoin::Message::GetHeaders.parse_from_payload(Bitcoin::Message::GetHeaders.new(70015, hashes).to_payload).hashes.size).to eq(101)
      payload = [70015].pack('V') + Bitcoin.pack_var_int(102) + ('aa' * 32).htb * 102 + ('00' * 32).htb
      expect { Bitcoin::Message::GetHeaders.parse_from_payload(payload) }.to raise_error(Bitcoin::Message::Error, 'getheaders locator size 102 exceeds 101.')
      expect { Bitcoin::Message::GetBlocks.parse_from_payload(payload) }.to raise_error(Bitcoin::Message::Error, 'getblocks locator size 102 exceeds 101.')
    end
  end
end
