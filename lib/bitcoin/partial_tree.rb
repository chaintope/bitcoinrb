module Bitcoin

  # A class for recovering partial from merkleblock message.
  # For a complete Merkle tree implementation, migrate to the merkle gem.
  class PartialTree

    # The maximum number of transactions a block can contain, so the maximum tx_count
    # a valid merkleblock message can commit to.
    MAX_TX_COUNT = MAX_BLOCK_WEIGHT / MIN_TRANSACTION_WEIGHT

    attr_accessor :root

    def initialize(root = nil)
      @root = root
    end

    def merkle_root
      root.value
    end

    # https://bitcoin.org/en/developer-reference#creating-a-merkleblock-message
    # The tree is read depth first the way Bitcoin Core's CPartialMerkleTree::TraverseAndExtract does, and
    # like Core it is rejected when the flags or the hashes run out, when a hash is left over, or when a flag
    # bit outside the padding of the last byte is left over.
    # @param [Integer] tx_count The number of transactions in the block.
    # @param [Array] hashes Array of hash values with hex format.
    # @param [String] flags The sequence of bits, a string of '0' and '1'.
    # @return [Bitcoin::PartialTree]
    # @raise [ArgumentError] If the given parameters are out of range or inconsistent.
    def self.build(tx_count, hashes, flags)
      validate!(tx_count, hashes, flags)
      bits = flags.each_char.map(&:to_i)
      root = build_initial_tree( Array.new(tx_count) { Node.new })
      used = { bits: 0, hashes: 0 }
      traverse(root, bits, hashes, used)
      raise ArgumentError, 'Invalid partial tree. Not every hash was used.' unless used[:hashes] == hashes.size
      raise ArgumentError, 'Invalid partial tree. Not every flag bit was used.' unless (used[:bits] + 7) / 8 == (bits.size + 7) / 8
      new(root)
    end

    # Validate the parameters of a partial merkle tree.
    # A merkleblock message is received from an untrusted peer, so these bounds are required
    # to stop it from making #build allocate an unbounded number of nodes or loop forever.
    # See Bitcoin Core's CPartialMerkleTree::ExtractMatches.
    # @raise [ArgumentError]
    def self.validate!(tx_count, hashes, flags)
      raise ArgumentError, 'tx_count must be greater than 0.' unless tx_count.is_a?(Integer) && tx_count > 0
      raise ArgumentError, "tx_count must be less than or equal to #{MAX_TX_COUNT}." if tx_count > MAX_TX_COUNT
      # There can never be more hashes provided than one for every txid.
      raise ArgumentError, 'hashes must not be greater than tx_count.' if hashes.size > tx_count
      # There must be at least one bit per node in the partial tree, and at least one node per hash.
      raise ArgumentError, 'flags must have at least one bit per hash.' if flags.size < hashes.size
    end

    # Read the flag bit of +node+ and, for a node which is neither a leaf nor the parent of a match, the
    # hash which stands for it. The right child of the last node of an odd level repeats the left one and
    # has no flag or hash of its own.
    # @raise [ArgumentError] If the flags or the hashes run out.
    def self.traverse(node, bits, hashes, used)
      raise ArgumentError, 'Invalid partial tree. The flags ran out.' if used[:bits] >= bits.size
      node.flag = bits[used[:bits]]
      used[:bits] += 1
      if node.flag.zero? || node.leaf?
        raise ArgumentError, 'Invalid partial tree. The hashes ran out.' if used[:hashes] >= hashes.size
        node.value = hashes[used[:hashes]]
        used[:hashes] += 1
      else
        traverse(node.left, bits, hashes, used)
        if node.right.duplicated
          node.right.value = node.left.value
        else
          traverse(node.right, bits, hashes, used)
        end
      end
    end
    private_class_method :traverse

    def self.build_initial_tree(nodes)
      raise ArgumentError, 'nodes must not be empty.' if nodes.empty?
      while nodes.size != 1
        nodes = nodes.each_slice(2).map { |m|
          parent = Node.new
          parent.left = m[0]
          parent.right = m[1] ? m[1] : m[0].dup.tap { |n| n.duplicated = true }
          parent
        }
      end
      nodes.first
    end

    def find_node(value)
      root.find_node(value)
    end

    # node of merkle tree
    class Node

      attr_accessor :flag
      attr_accessor :value
      attr_accessor :parent
      attr_accessor :left
      attr_accessor :right
      # Whether this node stands in for a missing right child, as the last node of a level with an odd
      # count is paired with a copy of itself. Such a copy is equal to its sibling by construction.
      attr_accessor :duplicated

      def initialize(value = nil)
        @value = value
        @duplicated = false
      end

      def left=(node)
        node.parent = self
        @left = node
      end

      def right=(node)
        node.parent = self
        @right = node
      end

      def value
        return @value if @value
        left_value, right_value = left.value, right.value
        # Two identical branches mean the hashes under them are not unique, which is how the duplicated
        # tx of CVE-2012-2459 hides in a merkleblock. Bitcoin Core marks such a tree as bad.
        raise ArgumentError, 'Invalid partial tree. The left and right branches are identical.' if !right.duplicated && left_value == right_value
        Bitcoin.double_sha256([left_value + right_value].pack('H*')).bth
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

      # calculate the depth of this node in the tree.
      def depth
        d = 0
        current_node = self
        until current_node.root? do
          current_node = current_node.parent
          d += 1
        end
        d
      end

      # @param target value to be found
      # @return node which has same value as target. nil if this node and any children don't have same value.
      def find_node(target)
        return self if value == target
        return nil if flag && flag.zero?
        return left&.find_node(target) || right&.find_node(target)
      end

      def index
        i = 0
        d = 1
        current_node = self
        until current_node.root? do
          i += d if current_node.parent.right == current_node
          current_node = current_node.parent
          d *= 2
        end
        i
      end
    end
  end
end
