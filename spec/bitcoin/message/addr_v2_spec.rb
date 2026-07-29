require 'spec_helper'

RSpec.describe Bitcoin::Message::AddrV2 do

  describe 'round-trip for each network' do
    subject {
      ipv4 = Bitcoin::Message::NetworkAddr.new(ip: '10.0.0.1', port: 8333, time: 1613286512)
      ipv6 = Bitcoin::Message::NetworkAddr.new(ip: '102:304:506:708:90a:b0c:d0e:f10', port: 8333, time: 1613286512,
                                               net: Bitcoin::Message::NETWORK_ID[:ipv6])
      tor_v2 = Bitcoin::Message::NetworkAddr.new(ip: nil, port: 8333, time: 1613286512,
                                                 net: Bitcoin::Message::NETWORK_ID[:tor_v2])
      tor_v2.addr = 'f1f2f3f4f5f6f7f8f9fa'
      tor_v3 = Bitcoin::Message::NetworkAddr.new(ip: nil, port: 8333, time: 1613286512,
                                                 net: Bitcoin::Message::NETWORK_ID[:tor_v3])
      tor_v3.addr = '79bcc625184b05194975c28b66b66b0469f7f6556fb1ac3189a79b40dda32f1f'
      i2p = Bitcoin::Message::NetworkAddr.new(ip: nil, port: 8333, time: 1613286512,
                                              net: Bitcoin::Message::NETWORK_ID[:i2p])
      i2p.addr = 'a2894dabaec08c0051a481a6dac88b64f98232ae42d4b6fd2fa81952dfe36a87'
      cjdns = Bitcoin::Message::NetworkAddr.new(ip: nil, port: 8333, time: 1613286512,
                                                net: Bitcoin::Message::NETWORK_ID[:cjdns])
      cjdns.addr = IPAddr.new('fc00:1:2:3:4:5:6:7')
      Bitcoin::Message::AddrV2.new([ipv4, ipv6, tor_v2, tor_v3, i2p, cjdns])
    }
    it 'should restore the original addrs' do
      parsed = Bitcoin::Message::AddrV2.parse_from_payload(subject.to_payload)
      expect(parsed.addrs.size).to eq(6)
      parsed.addrs.zip(subject.addrs) do |parsed_addr, original|
        expect(parsed_addr.net).to eq(original.net)
        expect(parsed_addr.addr).to eq(original.addr)
        expect(parsed_addr.port).to eq(original.port)
        expect(parsed_addr.time).to eq(original.time)
        expect(parsed_addr.services).to eq(original.services)
      end
      expect(parsed.to_payload).to eq(subject.to_payload)
    end
  end

  describe 'parse_from_payload without explicit stringio require' do
    it 'should parse payload' do
      script = "require 'bitcoin'; Bitcoin.chain_params = :mainnet; " \
                "v2 = Bitcoin::Message::AddrV2.parse_from_payload(['0170cc29600901047b7b7b00208d'].pack('H*')); " \
                "print v2.addrs.first.addr_string"
      output = `#{RbConfig.ruby} -I#{File.expand_path('../../../lib', __dir__)} -e "#{script}" 2>&1`
      expect(output).to eq('123.123.123.0')
    end
  end

  describe 'to_payload and parse_from_payload', network: :regtest do
    subject {
      Bitcoin::Message::Base.from_pkt('fabfb5da61646472763200000000000083000000c849f3b80a70cc29600901047b7b7b00208d71cc29600901047b7b7b01208e72cc29600901047b7b7b02208f73cc29600901047b7b7b03209074cc29600901047b7b7b04209175cc29600901047b7b7b05209276cc29600901047b7b7b06209377cc29600901047b7b7b07209478cc29600901047b7b7b08209579cc29600901047b7b7b092096'.htb)
    }
    it 'should parse payload' do
      expect(subject).to be_a(Bitcoin::Message::AddrV2)
      expect(subject.addrs.size).to eq(10)
      expect(subject.addrs[0].addr)
      expect(subject.addrs[0].net).to eq(Bitcoin::Message::NETWORK_ID[:ipv4])
      expect(subject.to_pkt.bth).to eq('fabfb5da61646472763200000000000083000000c849f3b80a70cc29600901047b7b7b00208d71cc29600901047b7b7b01208e72cc29600901047b7b7b02208f73cc29600901047b7b7b03209074cc29600901047b7b7b04209175cc29600901047b7b7b05209276cc29600901047b7b7b06209377cc29600901047b7b7b07209478cc29600901047b7b7b08209579cc29600901047b7b7b092096')
    end
  end

end