module Bitcoin
  module Taproot

    class Error < StandardError; end

    autoload :LeafNode, 'bitcoin/taproot/leaf_node'
    autoload :SimpleBuilder, 'bitcoin/taproot/simple_builder'
  end
end
