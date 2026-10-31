require 'spec_helper'

# Every message parser is fed data from a peer, so a payload which is cut short or is garbage has to be
# reported with an ArgumentError (Bitcoin::Message::Error is one) rather than by an exception from deep
# inside the parser, and a payload which does parse has to serialize back to the same bytes.
RSpec.describe 'Bitcoin::Message parse_from_payload', network: :mainnet do
  let(:header) { ('01000000' + '00' * 32 + '11' * 32 + '29ab5f49' + 'ffff001d' + '1dac2b7c').htb }
  let(:tx) { '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0100ffffffff0100f2052a01000000015100000000'.htb }
  let(:samples) do
    {
      Bitcoin::Message::Version => Bitcoin::Message::Version.new.to_payload,
      Bitcoin::Message::Addr => Bitcoin::Message::Addr.new([Bitcoin::Message::NetworkAddr.new]).to_payload,
      Bitcoin::Message::AddrV2 => Bitcoin::Message::AddrV2.new([Bitcoin::Message::NetworkAddr.new]).to_payload,
      Bitcoin::Message::Inv => Bitcoin::Message::Inv.new([Bitcoin::Message::Inventory.new(1, 'aa' * 32)]).to_payload,
      Bitcoin::Message::GetData => Bitcoin::Message::GetData.new([Bitcoin::Message::Inventory.new(1, 'aa' * 32)]).to_payload,
      Bitcoin::Message::NotFound => Bitcoin::Message::NotFound.new([Bitcoin::Message::Inventory.new(1, 'aa' * 32)]).to_payload,
      Bitcoin::Message::Headers => Bitcoin::Message::Headers.new([Bitcoin::BlockHeader.parse_from_payload(header)]).to_payload,
      Bitcoin::Message::GetHeaders => Bitcoin::Message::GetHeaders.new(70015, ['aa' * 32]).to_payload,
      Bitcoin::Message::GetBlocks => Bitcoin::Message::GetBlocks.new(70015, ['aa' * 32]).to_payload,
      Bitcoin::Message::Block => header + "\x01".b + tx,
      Bitcoin::Message::Tx => tx,
      Bitcoin::Message::MerkleBlock => header + [1].pack('V') + "\x01".b + 'aa'.htb * 32 + "\x01\x01".b,
      Bitcoin::Message::FilterLoad => Bitcoin::Message::FilterLoad.new(Bitcoin::BloomFilter.create_filter(10, 0.01)).to_payload,
      Bitcoin::Message::FilterAdd => Bitcoin::Message::FilterAdd.new('aa' * 20).to_payload,
      Bitcoin::Message::Ping => Bitcoin::Message::Ping.new(1).to_payload,
      Bitcoin::Message::Pong => Bitcoin::Message::Pong.new(1).to_payload,
      Bitcoin::Message::Reject => Bitcoin::Message::Reject.new('tx', 0x10, 'bad', 'aa' * 32).to_payload,
      Bitcoin::Message::FeeFilter => Bitcoin::Message::FeeFilter.new(1000).to_payload,
      Bitcoin::Message::SendCmpct => Bitcoin::Message::SendCmpct.new.to_payload,
      Bitcoin::Message::CmpctBlock => header + [1].pack('Q<') + "\x01".b + "\x11".b * 6 + "\x01\x00".b + tx,
      Bitcoin::Message::GetBlockTxn => 'aa'.htb * 32 + "\x02\x00\x01".b,
      Bitcoin::Message::BlockTxn => 'aa'.htb * 32 + "\x01".b + tx,
      Bitcoin::Message::GetCFilters => Bitcoin::Message::GetCFilters.new(0, 1, 'aa' * 32).to_payload,
      Bitcoin::Message::GetCFHeaders => Bitcoin::Message::GetCFHeaders.new(0, 1, 'aa' * 32).to_payload,
      Bitcoin::Message::GetCFCheckpt => Bitcoin::Message::GetCFCheckpt.new(0, 'aa' * 32).to_payload,
      Bitcoin::Message::CFCheckpt => Bitcoin::Message::CFCheckpt.new(0, 'aa' * 32, ['bb' * 32]).to_payload,
      Bitcoin::Message::CFHeaders => Bitcoin::Message::CFHeaders.new(0, 'aa' * 32, 'bb' * 32, ['cc' * 32]).to_payload,
      Bitcoin::Message::CFilter => Bitcoin::Message::CFilter.new(0, 'aa' * 32, 'ddee').to_payload,
      Bitcoin::Message::SendTxRcncl => Bitcoin::Message::SendTxRcncl.new(1, 2).to_payload
    }
  end

  it 'should parse its own serialization' do
    samples.each do |klass, payload|
      expect(klass.parse_from_payload(payload).to_payload).to eq(payload), klass.name
    end
  end

  it 'should report a truncated payload with an ArgumentError or parse a shorter valid encoding' do
    samples.each do |klass, payload|
      (0...payload.bytesize).each do |size|
        truncated = payload[0, size]
        begin
          parsed = klass.parse_from_payload(truncated)
        rescue ArgumentError
          next
        end
        # A prefix which parses is a valid shorter encoding, such as a ping without a nonce, and has to
        # serialize back to itself. A version message is the exception: Bitcoin Core reads a message of an old
        # protocol version which stops after the receiving address, and the fields it lacks are serialized
        # with their defaults.
        next if klass == Bitcoin::Message::Version
        expect(parsed.to_payload).to eq(truncated), "#{klass.name} accepted #{size} of #{payload.bytesize} bytes but does not serialize back to them"
      end
    end
  end

  it 'should report garbage with an ArgumentError or parse it' do
    random = Random.new(1)
    samples.each_key do |klass|
      50.times do
        garbage = random.bytes(random.rand(1..200))
        begin
          klass.parse_from_payload(garbage)
        rescue ArgumentError
          next
        rescue StandardError => e
          raise "#{klass.name} raised #{e.class} for #{garbage.bth}: #{e.message}"
        end
      end
    end
  end
end
