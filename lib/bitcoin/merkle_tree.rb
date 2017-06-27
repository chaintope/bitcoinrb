module Bitcoin

  # merkle tree
  class MerkleTree

    MODE_FULL = 0
    MODE_PARTIAL = 1

    attr_accessor :mode
    attr_accessor :root

    def initialize(mode = MODE_FULL, root = nil)
      @mode = mode
      @root = root
    end

    def self.build_from_leaf(txids)
      nodes = txids.each_slice(2).map{ |m|
        left = Node.new(m[0])
        right = Node.new(m[1] ? m[1] : m[0])
        [left, right]
      }.flatten
      while nodes.size != 1
        nodes = nodes.each_slice(2).map { |m|
          parent = Node.new
          parent.left = m[0]
          parent.right = m[1] ? m[1] : m[0]
          parent
        }
      end
      new(MODE_FULL, nodes.first)
    end

    # https://bitcoin.org/en/developer-reference#creating-a-merkleblock-message
    def self.build_partial(tx_count, hashes, flags)

    end

    def merkle_root
      root.hash
    end

  end

  # node of merkle tree
  class Node

    attr_accessor :flag
    attr_accessor :hash
    attr_accessor :parent
    attr_accessor :left
    attr_accessor :right

    def initialize(hash = nil)
      @hash = hash
    end

    def left=(node)
      node.parent = self
      @left = node
    end

    def right=(node)
      node.parent = self
      @right = node
    end

    def hash
      return @hash if @hash
      self.right = left unless self.right
      Digest::SHA256.digest(Digest::SHA256.digest(
          [right.hash + left.hash].pack('H*').reverse )).reverse.bth
    end

    def root?
      parent.nil?
    end

    def leaf?
      right.nil? && left.nil?
    end

    def partial?
      !flag.nil?
    end
  end

end
