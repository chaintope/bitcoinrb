require 'spec_helper'

describe Bitcoin::MerkleTree do

  describe 'build merkle tree' do
    subject {
      txids = ['270678dca40a26f6d3e2002c2d0cf6734c1cbfad5eebf40685c9586c36e498df',
               '22795697cc3dc124a54a5a3dcd44288f60aa41d5902cda3259f33c68c786272f',
               '25dee3cc8c0530022bbff38cdb1db3be64db02f65850a11ca03babe60c11fe1f',
               '9fb3eff6dd0418ae234dbe14a149fbe2e24540286d64078320a4a9bd9b439f64',
               'be3cb4790792625ac41892849c2dc71ac680be0a64e9e0712480c6f30fca1679',
               '13b68228983f635b7570259ee6f183a711374865761c74b59428ef27340b47c5',
               'b877c386668a0c2ef2e05f09ea881600e4fff91734c41dc47874010587594801',
               '59453382561569d7d818f8c2fec21d0a879434906697ad36f872a1cdfa93bd03',
               'a093e168031c7fdd06766ff525770067a881f4b889c4b6ef38fc7bcf80da4365',
               'ce8833f5aa9aea1c7359622d6431f0f0103ad5d45861f499d5bc233326c957b6',
               '0c157156b77c675bc9cfbfcef4bd2e5a515c6487b95b37ace070ce0ad51cb4bc',
               '0985bea40b0517de8073cead67febce38f15e248f1c626e29a803163f0acd975',
               'be0159e633914e8efe850c8fd73e8282cf7d4528fb55ecd252aa9bbf1d060319',
               'f40880b1bcc8a526b19f339ce53758a4534fe78d79f6842e92226d280b40391d',
               'efcde54107974cc635e76b9c66a32f2e7b2169f488b9e508a07b1231cea1ef6b',
               '7f08f9505f0343de2cdbbc759fa13b7c366b161027846c784470ed35e766bfac',
               'b1ab26badb91dc156d26b43f546a609fe382b810e1481b33daca608939a4beb4',
               'b462ccfef628accb300580cf5b6b29c144c53d73b9e0b2bf0dec2c0b94ee9cdc',
               '500e0ce5d092003915a8934480b65e087c9ecda2704ee0c5b16b0cbbcd4d609f',
               '00ecb5da85e1fdb525af6e74868fe700551093e0df1ef0124421f99761d1fc69',
               '0032ac5822e7b6801a39bc13ead901b8f5de302f70989d7d4a360bebab75b49d',
               '0183c521309cb773a222529150167698cd95ba9081b17f78651ccec01e62159e',
               '0158b7d72511eeff580f6eca430183dfbf348ffd889731299a13106b34beebad',
               '001bc3e43a899abc5d93e58df2b5b4731ae52aa0ee40f4f9e701c738fb0e4c11',
               '014987e1a794afb47b86667666f40e67dbefc20e47e525f1ca467d832edf3a1f',
               '00f8e6532865a75a8b4af9b35de91f677ad484d0722c08c9befe080df2ff7a4e',
               '25c01bddd3d770c35dfe80f6b075666ccf8272e0dfde33f20490e72d83df3c07',
               'c84d0fc39f992d3de54e2d4fc62559af91544355f280f651442afbd2e1603df8',
               'eda18fd515804ecde80dc980be0292b7e90a9afe19c4bfc7cff3db053125ad8f',
               '7023cc3f19394c78d59d2b18e553446db10e62ed68ed1b4b011a60d535ee3433',
               '82b098e66831757da57ffdda5b4e5ff1e6469b48eeb74cb41127a92086d75f63',
               '0e7f38fa77bdf46d9d1cd0a1ebcc2bf4268742202d1da1cd97ebbf483352c9bb',
               '4ae55ff3f5b94f389f60e847102c3bf7e61834bd5c9ac8873506d2d9a4c38460',
               'a63ceae8ce65ece6a1d216aea06a71013f6da0e23e154e6262797c96a868ef41',
               '5985c69d2de07bb54d53c32c2009377a7c1a08d39728b1582564c3ca73676827',
               'e8845daf2e73cb38fa392a5c85aa8aebf63e05cb3fe1443a259317447b58a620',
               'b4f93946ec0f34122a8e2f0028fb3b6aebd1f419f3edcc4e4629bdaba4b2f9d2']
      Bitcoin::MerkleTree.build_from_leaf(txids)
    }
    it 'should be build' do
      expect(subject.merkle_root).to eq('efe9af7a4024ca7fa104b5c82ff83c4b7be4a7b8df29faf5162658c44e0e388c')
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

    context 'include tx' do
      subject {
        hashes = ['5be239fdd6c626d196288bd2a4175258dc772370be25d52ea46a09ece54f6f9f',
                  '25dee3cc8c0530022bbff38cdb1db3be64db02f65850a11ca03babe60c11fe1f',
                  '9fb3eff6dd0418ae234dbe14a149fbe2e24540286d64078320a4a9bd9b439f64',
                  'be3cb4790792625ac41892849c2dc71ac680be0a64e9e0712480c6f30fca1679',
                  '13b68228983f635b7570259ee6f183a711374865761c74b59428ef27340b47c5',
                  '40ddc1b9e6ca0468bddce7446311e017fadeec71c288d75561e3e4d6ce7063d5',
                  'c3982fa65a45a199f3da9b1f7d2267de34a8691e895e910897e5d414b37172d5',
                  'e275bf259be142545769e80aa6421282994a9570277861efd0918f2a1fa8e4f3',
                  '43b1b38dc7acc589c2aeb9d458911cc477cc7aa9b523a7bcb6b247ab170db93a']
        Bitcoin::MerkleTree.build_partial(37, hashes, Bitcoin.byte_to_bit('5f1f00'.htb))
      }
      it 'should be build' do
        expect(subject.merkle_root).to eq('efe9af7a4024ca7fa104b5c82ff83c4b7be4a7b8df29faf5162658c44e0e388c')
      end
    end

  end

end
