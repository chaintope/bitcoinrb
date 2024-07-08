require 'spec_helper'

RSpec.describe Bitcoin::Taproot::CustomDepthBuilder do
  include Bitcoin::Descriptor

  describe "initialize" do
    it do
      expect{described_class.new(1, [])}.to raise_error(ArgumentError, "Internal public key must be string.")
      key = 'a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd'
      pk = pk('669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0').to_script
      tree = [
        Bitcoin::Taproot::LeafNode.new(pk),
        Bitcoin::Taproot::LeafNode.new(pk),
        Bitcoin::Taproot::LeafNode.new(pk)
      ]
      expect{described_class.new(key, tree)}.to raise_error(ArgumentError, "tree must be binary tree.")
      tree = [
        Bitcoin::Taproot::LeafNode.new(pk),
        [
          Bitcoin::Taproot::LeafNode.new(pk),
          Bitcoin::Taproot::LeafNode.new(pk),
          Bitcoin::Taproot::LeafNode.new(pk)
        ]
      ]
      expect{described_class.new(key, tree)}.to raise_error(ArgumentError, "tree must be binary tree.")
      # about normal case: see BIP-386 test case in descriptor_spec.rb
    end
  end

end