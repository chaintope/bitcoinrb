require 'spec_helper'

describe Bitcoin::Message::BlockTransactionRequest do

  let(:block_hash) { '9846a12e5eef1a4ba441233d76d3bcafb0bc4d86821dbb023971a91e839bf0f5' }

  it 'should round trip the differentially encoded indexes' do
    request = described_class.new(block_hash, [1, 2, 10, 0xffff])
    parsed = described_class.parse_from_payload(request.to_payload)
    expect(parsed.block_hash).to eq(block_hash)
    expect(parsed.indexes).to eq([1, 2, 10, 0xffff])
    expect(parsed.to_payload).to eq(request.to_payload)
  end

  it 'should reject an index count the payload cannot hold before allocating for it' do
    # 32 byte hash + 0xffffffff as the count (5 bytes) + one index. Each index needs at least one
    # byte, so this used to allocate an array of 4 billion entries.
    payload = block_hash.htb + "\xfe\xff\xff\xff\xff".b + "\x00".b
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    expect { described_class.parse_from_payload(payload) }.to raise_error(Bitcoin::Message::Error, /index count 4294967295 exceeds the payload/)
    expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).to be < 1
  end

  it 'should reject an index which overflows 16 bits' do
    # 0xffff then 0: the second index decodes to 0x10000.
    payload = block_hash.htb + "\x02".b + "\xfd\xff\xff".b + "\x00".b
    expect { described_class.parse_from_payload(payload) }.to raise_error(Bitcoin::Message::Error, /overflowed 16 bits/)
    # 0x10000 as the first index.
    payload = block_hash.htb + "\x01".b + "\xfe\x00\x00\x01\x00".b
    expect { described_class.parse_from_payload(payload) }.to raise_error(Bitcoin::Message::Error, /overflowed 16 bits/)
  end

  it 'should reject a truncated payload' do
    expect { described_class.parse_from_payload(block_hash.htb[0...31]) }.to raise_error(Bitcoin::Message::Error, /block hash is missing/)
    expect { described_class.parse_from_payload(block_hash.htb) }.to raise_error(Bitcoin::Message::Error, /index count is missing/)
    # Count 2 with a single one-byte index: the count check passes only when the bytes are there, so
    # make the second index a varint whose prefix is present but whose body is not.
    expect { described_class.parse_from_payload(block_hash.htb + "\x02\x00\xfd".b) }.to raise_error(Bitcoin::Message::Error, /index is missing/)
  end

end
