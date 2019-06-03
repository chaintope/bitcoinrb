require 'spec_helper'

describe Bitcoin::MerkleTree do

  describe 'build merkle tree' do
    subject {
      tx_hashes = ['df98e4366c58c98506f4eb5eadbf1c4c73f60c2d2c00e2d3f6260aa4dc780627',
               '2f2786c7683cf35932da2c90d541aa608f2844cd3d5a4aa524c13dcc97567922',
               '1ffe110ce6ab3ba01ca15058f602db64beb31ddb8cf3bf2b0230058ccce3de25',
               '649f439bbda9a4208307646d284045e2e2fb49a114be4d23ae1804ddf6efb39f',
               '7916ca0ff3c6802471e0e9640abe80c61ac72d9c849218c45a62920779b43cbe',
               'c5470b3427ef2894b5741c7665483711a783f1e69e2570755b633f982882b613',
               '0148598705017478c41dc43417f9ffe4001688ea095fe0f22e0c8a6686c377b8',
               '03bd93facda172f836ad9766903494870a1dc2fec2f818d8d769155682334559',
               '6543da80cf7bfc38efb6c489b8f481a867007725f56f7606dd7f1c0368e193a0',
               'b657c9263323bcd599f46158d4d53a10f0f031642d6259731cea9aaaf53388ce',
               'bcb41cd50ace70e0ac375bb987645c515a2ebdf4cebfcfc95b677cb75671150c',
               '75d9acf06331809ae226c6f148e2158fe3bcfe67adce7380de17050ba4be8509',
               '1903061dbf9baa52d2ec55fb28457dcf82823ed78f0c85fe8e4e9133e65901be',
               '1d39400b286d22922e84f6798de74f53a45837e59c339fb126a5c8bcb18008f4',
               '6befa1ce31127ba008e5b988f469217b2e2fa3669c6be735c64c970741e5cdef',
               'acbf66e735ed7044786c842710166b367c3ba19f75bcdb2cde43035f50f9087f',
               'b4bea4398960cada331b48e110b882e39f606a543fb4266d15dc91dbba26abb1',
               'dc9cee940b2cec0dbfb2e0b9733dc544c1296b5bcf800530cbac28f6fecc62b4',
               '9f604dcdbb0c6bb1c5e04e70a2cd9e7c085eb6804493a815390092d0e50c0e50',
               '69fcd16197f9214412f01edfe093105500e78f86746eaf25b5fde185dab5ec00',
               '9db475abeb0b364a7d9d98702f30def5b801d9ea13bc391a80b6e72258ac3200',
               '9e15621ec0ce1c65787fb18190ba95cd98761650915222a273b79c3021c58301',
               'adebbe346b10139a29319788fd8f34bfdf830143ca6e0f58ffee1125d7b75801',
               '114c0efb38c701e7f9f440eea02ae51a73b4b5f28de5935dbc9a893ae4c31b00',
               '1f3adf2e837d46caf125e5470ec2efdb670ef4667666867bb4af94a7e1874901',
               '4e7afff20d08febec9082c72d084d47a671fe95db3f94a8b5aa7652853e6f800',
               '073cdf832de79004f233dedfe07282cf6c6675b0f680fe5dc370d7d3dd1bc025',
               'f83d60e1d2fb2a4451f680f255435491af5925c64f2d4ee53d2d999fc30f4dc8',
               '8fad253105dbf3cfc7bfc419fe9a0ae9b79202be80c90de8cd4e8015d58fa1ed',
               '3334ee35d5601a014b1bed68ed620eb16d4453e5182b9dd5784c39193fcc2370',
               '635fd78620a92711b44cb7ee489b46e6f15f4e5bdafd7fa57d753168e698b082',
               'bbc9523348bfeb97cda11d2d20428726f42bcceba1d01c9d6df4bd77fa387f0e',
               '6084c3a4d9d2063587c89a5cbd3418e6f73b2c1047e8609f384fb9f5f35fe54a',
               '41ef68a8967c7962624e153ee2a06d3f01716aa0ae16d2a1e6ec65cee8ea3ca6',
               '27686773cac3642558b12897d3081a7c7a3709202cc3534db57be02d9dc68559',
               '20a6587b441793253a44e13fcb053ef6eb8aaa855c2a39fa38cb732eaf5d84e8',
               'd2f9b2a4abbd29464eccedf319f4d1eb6a3bfb28002f8e2a12340fec4639f9b4']
      Bitcoin::MerkleTree.build_from_leaf(tx_hashes)
    }
    it 'should be build' do
      expect(subject.merkle_root).to eq('8c380e4ec4582616f5fa29dfb8a7e47b4b3cf82fc8b504a17fca24407aafe9ef')
    end

    context 'include coinbase tx only' do
      subject {
        tx_hashes = ['36a39ed285a4ffdb141c16af1eb1029bf18a18a7fdc54c70561d9371714f0c74']
        Bitcoin::MerkleTree.build_from_leaf(tx_hashes)
      }
      it 'should be build' do
        expect(subject.merkle_root).to eq('36a39ed285a4ffdb141c16af1eb1029bf18a18a7fdc54c70561d9371714f0c74')
      end
    end
  end

  describe 'build partial merkle tree' do

    context 'not include tx' do
      subject {
        hashes = ['5be239fdd6c626d196288bd2a4175258dc772370be25d52ea46a09ece54f6f9f']
        Bitcoin::MerkleTree.build_partial(37, hashes, Bitcoin.byte_to_bit('00'.htb))
      }
      it 'should be build' do
        expect(subject.merkle_root).to eq('5be239fdd6c626d196288bd2a4175258dc772370be25d52ea46a09ece54f6f9f')
      end
    end

    context 'include coinbase tx only' do
      subject {
        hashes = ['36a39ed285a4ffdb141c16af1eb1029bf18a18a7fdc54c70561d9371714f0c74']
        Bitcoin::MerkleTree.build_partial(1, hashes, Bitcoin.byte_to_bit('01'.htb))
      }
      it 'should be build' do
        expect(subject.merkle_root).to eq('36a39ed285a4ffdb141c16af1eb1029bf18a18a7fdc54c70561d9371714f0c74')
      end
    end

    context 'include tx' do
      subject {
        # 000000000000b731f2eef9e8c63173adfb07e41bd53eb0ef0a6b720d6cb6dea4 mainnet block
        hashes = ['3612262624047ee87660be1a707519a443b1c1ce3d248cbfc6c15870f6c5daa2',
                  '019f5b01d4195ecbc9398fbf3c3b1fa9bb3183301d7a1fb3bd174fcfa40a2b65',
                  '41ed70551dd7e841883ab8f0b16bf04176b7d1480e4f0af9f3d4c3595768d068',
                  '20d2a7bc994987302e5b1ac80fc425fe25f8b63169ea78e68fbaaefa59379bbf']
        Bitcoin::MerkleTree.build_partial(7, hashes, Bitcoin.byte_to_bit('1d'.htb))
      }
      it 'should be build' do
        expect(subject.merkle_root).to eq('7f16c5962e8bd963659c793ce370d95f093bc7e367117b3c30c1f8fdd0d97287')
      end
    end
  end

  describe 'find_node' do
    let(:tree) do
      # H1 = 3612262624047ee87660be1a707519a443b1c1ce3d248cbfc6c15870f6c5daa2
      # H2 = 019f5b01d4195ecbc9398fbf3c3b1fa9bb3183301d7a1fb3bd174fcfa40a2b65
      # H3 = 41ed70551dd7e841883ab8f0b16bf04176b7d1480e4f0af9f3d4c3595768d068
      # H4 = 20d2a7bc994987302e5b1ac80fc425fe25f8b63169ea78e68fbaaefa59379bbf
      hashes = ['3612262624047ee87660be1a707519a443b1c1ce3d248cbfc6c15870f6c5daa2',
                '019f5b01d4195ecbc9398fbf3c3b1fa9bb3183301d7a1fb3bd174fcfa40a2b65',
                '41ed70551dd7e841883ab8f0b16bf04176b7d1480e4f0af9f3d4c3595768d068',
                '20d2a7bc994987302e5b1ac80fc425fe25f8b63169ea78e68fbaaefa59379bbf']
      Bitcoin::MerkleTree.build_partial(7, hashes, Bitcoin.byte_to_bit('1d'.htb))
    end

    context 'hash is merkle root' do
      subject { tree.find_node('7f16c5962e8bd963659c793ce370d95f093bc7e367117b3c30c1f8fdd0d97287') }
      it 'should return root node' do
        expect(subject.leaf?).to be_falsy
        expect(subject.index).to eq 0
        expect(subject.depth).to eq 0
      end
    end

    context 'inner node has hash H1' do
      subject { tree.find_node('3612262624047ee87660be1a707519a443b1c1ce3d248cbfc6c15870f6c5daa2') }
      it 'should return inner node' do
        expect(subject.leaf?).to be_falsy
        expect(subject.index).to eq 0
        expect(subject.depth).to eq 1
      end
    end

    context 'leaf node has hash H2' do
      subject { tree.find_node('019f5b01d4195ecbc9398fbf3c3b1fa9bb3183301d7a1fb3bd174fcfa40a2b65') }
      it 'should return leaf node' do
        expect(subject.leaf?).to be_truthy
        expect(subject.index).to eq 4
        expect(subject.depth).to eq 3
      end
    end

    context 'leaf node has hash H3' do
      subject { tree.find_node('41ed70551dd7e841883ab8f0b16bf04176b7d1480e4f0af9f3d4c3595768d068') }
      it 'should return inner node' do
        expect(subject.leaf?).to be_truthy
        expect(subject.index).to eq 5
        expect(subject.depth).to eq 3
      end
    end

    context 'inner node has hash d(H2 + H3)' do
      # double hash of (019f5b01d4195ecbc9398fbf3c3b1fa9bb3183301d7a1fb3bd174fcfa40a2b65 || 41ed70551dd7e841883ab8f0b16bf04176b7d1480e4f0af9f3d4c3595768d068)
      subject { tree.find_node('323a54ad9aa4ba42d1edfb9519af995cf93b736364f81a090885b61b6d7ee1ca') }
      it 'should return inner node' do
        expect(subject.leaf?).to be_falsy
        expect(subject.index).to eq 2
        expect(subject.depth).to eq 2
      end
    end

    context 'inner node has hash H4' do
      subject { tree.find_node('20d2a7bc994987302e5b1ac80fc425fe25f8b63169ea78e68fbaaefa59379bbf') }
      it 'should return inner node' do
        expect(subject.leaf?).to be_falsy
        expect(subject.index).to eq 3
        expect(subject.depth).to eq 2
      end
    end

    context 'inner node has hash d(d(H2 + H3) + H4)' do
      # double hash of (323a54ad9aa4ba42d1edfb9519af995cf93b736364f81a090885b61b6d7ee1ca || 20d2a7bc994987302e5b1ac80fc425fe25f8b63169ea78e68fbaaefa59379bbf)
      subject { tree.find_node('cfbc39264b50034b71abba2d4eb0220ad66bf8ffde47d42b32b199accbdca739') }
      it 'should return inner node' do
        expect(subject.leaf?).to be_falsy
        expect(subject.index).to eq 1
        expect(subject.depth).to eq 1
      end
    end

    context 'hash is not in tree' do
      subject { tree.find_node('0000000000000000000000000000000000000000000000000000000000000000') }
      it 'should return nil' do
        expect(subject).to be_nil
      end
    end

    context 'find final txid in tree which has odd number of txids' do
      let(:tree) do
        hashes = ["eabc5a0f2db047073fd8bcc8317b72578f705a0845b33d3c0fa939421219a452", "15157a0138efe2d76ca0ef26f4b42341bd14ff2871603e7364a1d404da51493f"]
        Bitcoin::MerkleTree.build_partial(3, hashes, Bitcoin.byte_to_bit('1d'.htb))
      end

      subject { tree.find_node('15157a0138efe2d76ca0ef26f4b42341bd14ff2871603e7364a1d404da51493f') }
      it 'should return nil' do
        expect(subject.leaf?).to be_truthy
        expect(subject.index).to eq 2
        expect(subject.depth).to eq 2
      end
    end

    context 'tree is built by using #build_from_leaf' do
      let(:tree) do
        tx_hashes = ['df98e4366c58c98506f4eb5eadbf1c4c73f60c2d2c00e2d3f6260aa4dc780627',
                 '2f2786c7683cf35932da2c90d541aa608f2844cd3d5a4aa524c13dcc97567922',
                 '1ffe110ce6ab3ba01ca15058f602db64beb31ddb8cf3bf2b0230058ccce3de25',
                 '649f439bbda9a4208307646d284045e2e2fb49a114be4d23ae1804ddf6efb39f',
                 '7916ca0ff3c6802471e0e9640abe80c61ac72d9c849218c45a62920779b43cbe',
                 'c5470b3427ef2894b5741c7665483711a783f1e69e2570755b633f982882b613',
                 '0148598705017478c41dc43417f9ffe4001688ea095fe0f22e0c8a6686c377b8',
                 '03bd93facda172f836ad9766903494870a1dc2fec2f818d8d769155682334559',
                 '6543da80cf7bfc38efb6c489b8f481a867007725f56f7606dd7f1c0368e193a0',
                 'b657c9263323bcd599f46158d4d53a10f0f031642d6259731cea9aaaf53388ce',
                 'bcb41cd50ace70e0ac375bb987645c515a2ebdf4cebfcfc95b677cb75671150c',
                 '75d9acf06331809ae226c6f148e2158fe3bcfe67adce7380de17050ba4be8509',
                 '1903061dbf9baa52d2ec55fb28457dcf82823ed78f0c85fe8e4e9133e65901be',
                 '1d39400b286d22922e84f6798de74f53a45837e59c339fb126a5c8bcb18008f4',
                 '6befa1ce31127ba008e5b988f469217b2e2fa3669c6be735c64c970741e5cdef',
                 'acbf66e735ed7044786c842710166b367c3ba19f75bcdb2cde43035f50f9087f',
                 'b4bea4398960cada331b48e110b882e39f606a543fb4266d15dc91dbba26abb1',
                 'dc9cee940b2cec0dbfb2e0b9733dc544c1296b5bcf800530cbac28f6fecc62b4',
                 '9f604dcdbb0c6bb1c5e04e70a2cd9e7c085eb6804493a815390092d0e50c0e50',
                 '69fcd16197f9214412f01edfe093105500e78f86746eaf25b5fde185dab5ec00',
                 '9db475abeb0b364a7d9d98702f30def5b801d9ea13bc391a80b6e72258ac3200',
                 '9e15621ec0ce1c65787fb18190ba95cd98761650915222a273b79c3021c58301',
                 'adebbe346b10139a29319788fd8f34bfdf830143ca6e0f58ffee1125d7b75801',
                 '114c0efb38c701e7f9f440eea02ae51a73b4b5f28de5935dbc9a893ae4c31b00',
                 '1f3adf2e837d46caf125e5470ec2efdb670ef4667666867bb4af94a7e1874901',
                 '4e7afff20d08febec9082c72d084d47a671fe95db3f94a8b5aa7652853e6f800',
                 '073cdf832de79004f233dedfe07282cf6c6675b0f680fe5dc370d7d3dd1bc025',
                 'f83d60e1d2fb2a4451f680f255435491af5925c64f2d4ee53d2d999fc30f4dc8',
                 '8fad253105dbf3cfc7bfc419fe9a0ae9b79202be80c90de8cd4e8015d58fa1ed',
                 '3334ee35d5601a014b1bed68ed620eb16d4453e5182b9dd5784c39193fcc2370',
                 '635fd78620a92711b44cb7ee489b46e6f15f4e5bdafd7fa57d753168e698b082',
                 'bbc9523348bfeb97cda11d2d20428726f42bcceba1d01c9d6df4bd77fa387f0e',
                 '6084c3a4d9d2063587c89a5cbd3418e6f73b2c1047e8609f384fb9f5f35fe54a',
                 '41ef68a8967c7962624e153ee2a06d3f01716aa0ae16d2a1e6ec65cee8ea3ca6',
                 '27686773cac3642558b12897d3081a7c7a3709202cc3534db57be02d9dc68559',
                 '20a6587b441793253a44e13fcb053ef6eb8aaa855c2a39fa38cb732eaf5d84e8',
                 'd2f9b2a4abbd29464eccedf319f4d1eb6a3bfb28002f8e2a12340fec4639f9b4']
        Bitcoin::MerkleTree.build_from_leaf(tx_hashes)
      end

      subject { tree.find_node('75d9acf06331809ae226c6f148e2158fe3bcfe67adce7380de17050ba4be8509') }
      it 'should return leaf node' do
        expect(subject.leaf?).to be_truthy
        expect(subject.index).to eq 11
        expect(subject.depth).to eq 6
      end
    end
  end
end
