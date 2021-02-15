require 'spec_helper'

describe Bitcoin::Message::NetworkAddr do

  describe '#parse_from_payload' do
    subject {
      Bitcoin::Message::NetworkAddr.parse_from_payload('010000000000000000000000000000000000ffffc61b6409208d'.htb)
    }
    it 'should be parsed' do
      expect(subject.addr_string).to eq('198.27.100.9')
      expect(subject.port).to eq(8333)
      expect(subject.services).to eq(1)
      expect(subject.to_payload(true).bth).to eq('010000000000000000000000000000000000ffffc61b6409208d')
    end

    context 'IPv6' do
      it 'should be processed.' do
        a = Bitcoin::Message::NetworkAddr.parse_from_payload('70cc29600902100102030405060708090a0b0c0d0e0f1000'.htb,
                                                             type: Bitcoin::Message::NetworkAddr::TYPE[:addr_v2])
        expect(a.addr_string).to eq('102:304:506:708:90a:b0c:d0e:f10')
        #  Valid IPv6, contains embedded "internal".
        a = Bitcoin::Message::NetworkAddr.parse_from_payload('70cc2960090210fd6b88c08724ca978112ca1bbdcafac200'.htb,
                                                             type: Bitcoin::Message::NetworkAddr::TYPE[:addr_v2])
        expect(a.addr_string).to eq('zklycewkdo64v6wc.internal')
        # Invalid IPv6, with bogus length.
        expect{Bitcoin::Message::NetworkAddr.parse_from_payload(
          '70cc29600902040000'.htb, type: Bitcoin::Message::NetworkAddr::TYPE[:addr_v2])}.
          to raise_error(Bitcoin::Message::Error, 'Invalid IPv6 address.')
        # Invalid IPv6, contains embedded IPv4.
        expect{Bitcoin::Message::NetworkAddr.parse_from_payload(
          '70cc296009021000000000000000000000ffff01020304'.htb, type: Bitcoin::Message::NetworkAddr::TYPE[:addr_v2])}.
          to raise_error(Bitcoin::Message::Error, 'Invalid IPv6 address.')
      end
    end

    context 'Tor v2' do
      it 'should be processed.' do
        a = Bitcoin::Message::NetworkAddr.parse_from_payload('70cc296009030af1f2f3f4f5f6f7f8f9fa00'.htb,
                                                             type: Bitcoin::Message::NetworkAddr::TYPE[:addr_v2])
        expect(a.addr_string).to eq('6hzph5hv6337r6p2.onion')
        # Invalid tor v2, with bogus length.
        expect{Bitcoin::Message::NetworkAddr.parse_from_payload(
          '70cc29600903070000'.htb, type: Bitcoin::Message::NetworkAddr::TYPE[:addr_v2])}.
          to raise_error(Bitcoin::Message::Error, 'Invalid Tor v2 address.')
      end
    end

    context 'Tor v3' do
      it 'should be processed.' do
        a = Bitcoin::Message::NetworkAddr.parse_from_payload('70cc296009042079bcc625184b05194975c28b66b66b0469f7f6556fb1ac3189a79b40dda32f1f00'.htb,
                                                             type: Bitcoin::Message::NetworkAddr::TYPE[:addr_v2])
        expect(a.addr_string).to eq('pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion')
        # Invalid tor v3, with bogus length.
        expect{Bitcoin::Message::NetworkAddr.parse_from_payload(
          '70cc29600904000000'.htb, type: Bitcoin::Message::NetworkAddr::TYPE[:addr_v2])}.
          to raise_error(Bitcoin::Message::Error, 'Invalid Tor v3 address.')
      end
    end

    context 'I2P' do
      it 'should be processed.' do
        a = Bitcoin::Message::NetworkAddr.parse_from_payload('70cc2960090520a2894dabaec08c0051a481a6dac88b64f98232ae42d4b6fd2fa81952dfe36a8700'.htb,
                                                             type: Bitcoin::Message::NetworkAddr::TYPE[:addr_v2])
        expect(a.addr_string).to eq('ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p')
        # Invalid I2P, with bogus length.
        expect{Bitcoin::Message::NetworkAddr.parse_from_payload(
          '70cc29600905030000'.htb, type: Bitcoin::Message::NetworkAddr::TYPE[:addr_v2])}.
          to raise_error(Bitcoin::Message::Error, 'Invalid I2P address.')
      end
    end

    context 'CJDNS' do
      it 'should be processed.' do
        a = Bitcoin::Message::NetworkAddr.parse_from_payload('70cc2960090610fc00000100020003000400050006000700'.htb,
                                                             type: Bitcoin::Message::NetworkAddr::TYPE[:addr_v2])
        expect(a.addr_string).to eq('fc00:1:2:3:4:5:6:7')
        # Invalid CJDNS, wrong prefix.
        expect{Bitcoin::Message::NetworkAddr.parse_from_payload(
          '70cc2960090610aa00000100020003000400050006000700'.htb, type: Bitcoin::Message::NetworkAddr::TYPE[:addr_v2])}.
          to raise_error(Bitcoin::Message::Error, 'Invalid CJDNS address.')
        # Invalid CJDNS, with bogus length.
        expect{Bitcoin::Message::NetworkAddr.parse_from_payload(
          '70cc29600906fe000000020102030405060700'.htb, type: Bitcoin::Message::NetworkAddr::TYPE[:addr_v2])}.
          to raise_error(Bitcoin::Message::Error, 'Invalid CJDNS address.')
      end
    end

    context 'unknown network id' do
      it 'should raise error.' do
        expect{Bitcoin::Message::NetworkAddr.parse_from_payload(
          '70cc296009aa040102030400'.htb, type: Bitcoin::Message::NetworkAddr::TYPE[:addr_v2])}.
          to raise_error(Bitcoin::Message::Error, 'Unknown network id: 170')
        expect{Bitcoin::Message::NetworkAddr.parse_from_payload(
          '70cc296009aa0000'.htb, type: Bitcoin::Message::NetworkAddr::TYPE[:addr_v2])}.
          to raise_error(Bitcoin::Message::Error, 'Unknown network id: 170')
      end
    end
  end

  describe '#to_payload' do
    subject {
      p = Bitcoin::Message::NetworkAddr.new(port: 18333).to_payload(true)
      Bitcoin::Message::NetworkAddr.parse_from_payload(p)
    }
    it 'should be generate payload' do
      expect(subject.port).to eq(18333)
      expect(subject.addr_string).to eq('127.0.0.1')
      expect(subject.services).to eq(Bitcoin::Message::DEFAULT_SERVICE_FLAGS)
    end
  end

end