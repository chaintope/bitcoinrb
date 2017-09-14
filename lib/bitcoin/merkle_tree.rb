module Bitcoin

  # merkle tree
  class MerkleTree

    attr_accessor :root

    def initialize(root = nil)
      @root = root
    end

    def merkle_root
      root.hash
    end

    def self.build_from_leaf(txids)
      nodes = txids.each_slice(2).map{ |m|
        left = Node.new(m[0])
        right = Node.new(m[1] ? m[1] : m[0])
        [left, right]
      }.flatten
      new(build_initial_tree(nodes))
    end

    # https://bitcoin.org/en/developer-reference#creating-a-merkleblock-message
    def self.build_partial(tx_count, hashes, flags)
      flags = flags.each_char.map(&:to_i)
      root = build_initial_tree( Array.new(tx_count) { Node.new })
      current_node = root
      hash_index = 0
      flags.each do |f|
        current_node.flag = f
        if f.zero? || current_node.leaf?
          current_node.hash = hashes[hash_index]
          hash_index += 1
        end
        current_node = current_node.next_partial
        break if hash_index == hashes.size
      end
      new(root)
    end

    def self.build_initial_tree(nodes)
      while nodes.size != 1
        nodes = nodes.each_slice(2).map { |m|
          parent = Node.new
          parent.left = m[0]
          parent.right = m[1] ? m[1] : m[0].dup
          parent
        }
      end
      nodes.first
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
        self.right = left.dup unless right
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

      def next_partial
        return nil if root? && (flag.zero? || (left.partial? && right.partial?))
        return parent.next_partial if flag.zero? || leaf?
        return left unless left.partial?
        self.right = left.dup unless right
        right.partial? ? parent.next_partial : right
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

    end
  end

end
