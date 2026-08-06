require 'spec_helper'

describe Bitcoin::Message::MerkleBlock do

  describe 'parse from payload' do
    subject {
      Bitcoin::Message::MerkleBlock.parse_from_payload('00000020ac70b03084a595f8b06c4de338ff14b6953a96cb5ce44a5ffe66f760000000008c380e4ec4582616f5fa29dfb8a7e47b4b3cf82fc8b504a17fca24407aafe9ef04a95159ffff001def07843825000000099f6f4fe5ec096aa42ed525be702377dc585217a4d28b2896d126c6d6fd39e25b1ffe110ce6ab3ba01ca15058f602db64beb31ddb8cf3bf2b0230058ccce3de25649f439bbda9a4208307646d284045e2e2fb49a114be4d23ae1804ddf6efb39f7916ca0ff3c6802471e0e9640abe80c61ac72d9c849218c45a62920779b43cbec5470b3427ef2894b5741c7665483711a783f1e69e2570755b633f982882b613d56370ced6e4e36155d788c271ecdefa17e0116344e7dcbd6804cae6b9c1dd40d57271b314d4e59708915e891e69a834de67227d1f9bdaf399a1455aa62f98c3f3e4a81f2a8f91d0ef61782770954a99821242a60ae869575442e19b25bf75e23ab90d17ab47b2b6bca723b5a97acc77c41c9158d4b9aec289c5acc78db3b143035f1f00'.htb)
    }
    it 'should be parsed' do
      expect(subject.header.block_hash).to eq('20fba08e639454ffc3dc1b6c1dd5ae934fd14ab98b90284fd9b1474a00000000')
      expect(subject.header.merkle_root).to eq('8c380e4ec4582616f5fa29dfb8a7e47b4b3cf82fc8b504a17fca24407aafe9ef')
      expect(subject.tx_count).to eq(37)
      expect(subject.flags).to eq('5f1f00')
      partial_tree = subject.partial_tree
      expect(partial_tree.merkle_root).to eq(subject.header.merkle_root)
    end

    # Build a merkleblock payload with an arbitrary tx_count, which a peer fully controls.
    def build_payload(tx_count, hash_count: 1, flags: '00')
      header = '00000020ac70b03084a595f8b06c4de338ff14b6953a96cb5ce44a5ffe66f760000000008c380e4ec4582616f5fa29dfb8a7e47b4b3cf82fc8b504a17fca24407aafe9ef04a95159ffff001def078438'
      payload = header.htb << [tx_count].pack('V')
      payload << Bitcoin.pack_var_int(hash_count) << ('9f6f4fe5ec096aa42ed525be702377dc585217a4d28b2896d126c6d6fd39e25b'.htb * hash_count)
      payload << Bitcoin.pack_var_int(flags.htb.bytesize) << flags.htb
      payload
    end

    context 'tx_count is 0' do
      subject { Bitcoin::Message::MerkleBlock.parse_from_payload(build_payload(0)) }
      it 'should raise error' do
        expect { subject }.to raise_error(Bitcoin::Message::Error, 'tx_count must be greater than 0.')
      end
    end

    context 'tx_count exceeds the maximum' do
      subject { Bitcoin::Message::MerkleBlock.parse_from_payload(build_payload(0xffffffff)) }
      it 'should raise error' do
        expect { subject }.to raise_error(
          Bitcoin::Message::Error, "tx_count must be less than or equal to #{Bitcoin::PartialTree::MAX_TX_COUNT}.")
      end
    end

    context 'hashes is greater than tx_count' do
      subject { Bitcoin::Message::MerkleBlock.parse_from_payload(build_payload(1, hash_count: 2)) }
      it 'should raise error' do
        expect { subject }.to raise_error(Bitcoin::Message::Error, 'hashes must not be greater than tx_count.')
      end
    end
  end

  describe 'to_pkt' do
    subject {
      m = Bitcoin::Message::MerkleBlock.new
      m.header = Bitcoin::BlockHeader.parse_from_payload('00000020ac70b03084a595f8b06c4de338ff14b6953a96cb5ce44a5ffe66f760000000008c380e4ec4582616f5fa29dfb8a7e47b4b3cf82fc8b504a17fca24407aafe9ef04a95159ffff001def078438'.htb)
      m.hashes = ['9f6f4fe5ec096aa42ed525be702377dc585217a4d28b2896d126c6d6fd39e25b',
                  '1ffe110ce6ab3ba01ca15058f602db64beb31ddb8cf3bf2b0230058ccce3de25',
                  '649f439bbda9a4208307646d284045e2e2fb49a114be4d23ae1804ddf6efb39f',
                  '7916ca0ff3c6802471e0e9640abe80c61ac72d9c849218c45a62920779b43cbe',
                  'c5470b3427ef2894b5741c7665483711a783f1e69e2570755b633f982882b613',
                  'd56370ced6e4e36155d788c271ecdefa17e0116344e7dcbd6804cae6b9c1dd40',
                  'd57271b314d4e59708915e891e69a834de67227d1f9bdaf399a1455aa62f98c3',
                  'f3e4a81f2a8f91d0ef61782770954a99821242a60ae869575442e19b25bf75e2',
                  '3ab90d17ab47b2b6bca723b5a97acc77c41c9158d4b9aec289c5acc78db3b143',]
      m.tx_count = 37
      m.flags = '5f1f00'
      m.to_pkt
    }
    it 'should be generate' do
      expect(subject).to eq('0b1109076d65726b6c65626c6f636b007901000005d2dedd00000020ac70b03084a595f8b06c4de338ff14b6953a96cb5ce44a5ffe66f760000000008c380e4ec4582616f5fa29dfb8a7e47b4b3cf82fc8b504a17fca24407aafe9ef04a95159ffff001def07843825000000099f6f4fe5ec096aa42ed525be702377dc585217a4d28b2896d126c6d6fd39e25b1ffe110ce6ab3ba01ca15058f602db64beb31ddb8cf3bf2b0230058ccce3de25649f439bbda9a4208307646d284045e2e2fb49a114be4d23ae1804ddf6efb39f7916ca0ff3c6802471e0e9640abe80c61ac72d9c849218c45a62920779b43cbec5470b3427ef2894b5741c7665483711a783f1e69e2570755b633f982882b613d56370ced6e4e36155d788c271ecdefa17e0116344e7dcbd6804cae6b9c1dd40d57271b314d4e59708915e891e69a834de67227d1f9bdaf399a1455aa62f98c3f3e4a81f2a8f91d0ef61782770954a99821242a60ae869575442e19b25bf75e23ab90d17ab47b2b6bca723b5a97acc77c41c9158d4b9aec289c5acc78db3b143035f1f00'.htb)
    end
  end

end
