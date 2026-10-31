module Bitcoin
  class Block

    attr_accessor :header
    attr_accessor :transactions

    # Constructor
    # @param [Bitcoin::BlockHeader] header
    # @param [Array] transactions An array of transaction.
    # @raise [ArgumentError]
    def initialize(header, transactions = [])
      raise ArgumentError, "header must be Bitcoin::BlockHeader." unless header.is_a?(Bitcoin::BlockHeader)
      raise ArgumentError, "transactions must be an Array." unless transactions.is_a?(Array)
      @header = header
      @transactions = transactions
    end

    # Create genesis block.
    # @param [String] msg Message embedded in coinbase transaction.
    # @param [Bitcoin::Script] script Coinbase transaction scriptPubkey.
    # @param [Integer] time Block time.
    # @param [Integer] nonce nonce.
    # @param [Integer] bits nBits
    # @param [Integer] version nVersion.
    # @param [Integer] rewards Block rewards(satoshi).
    def self.create_genesis(msg, script, time, nonce, bits, version, rewards = 50 * 100000000)
      coinbase = Bitcoin::Tx.create_coinbase(msg, script, rewards)
      header = BlockHeader.new(
        version,
        '00' * 32,
        Merkle::BinaryTree.new(config: Merkle::Config.bitcoin(element_encoding: :hex), leaves: [coinbase.txid]).compute_root.rhex,
        time,
        bits,
        nonce
      )
      Block.new(header, [coinbase])
    end

    def self.parse_from_payload(payload)
      Bitcoin::Message::Block.parse_from_payload(payload).to_block
    end

    def hash
      header.hash
    end

    def block_hash
      header.block_hash
    end

    # calculate block weight
    def weight
      stripped_size * (WITNESS_SCALE_FACTOR - 1) + size
    end

    # calculate total size (include witness data.)
    def size
      80 + Bitcoin.pack_var_int(transactions.size).bytesize +
          transactions.inject(0){|sum, tx| sum + (tx.witness? ? tx.serialize_witness_format.bytesize : tx.serialize_old_format.bytesize)}
    end

    # calculate base size (not include witness data.)
    def stripped_size
      80 + Bitcoin.pack_var_int(transactions.size).bytesize +
          transactions.inject(0){|sum, tx| sum + tx.serialize_old_format.bytesize}
    end

    # check the merkle root in the block header matches merkle root calculated from tx list.
    # A tx list with the duplication of CVE-2012-2459 is reported as invalid even though its root
    # matches, as Bitcoin Core does, since the same root also belongs to the list without the duplicate.
    def valid_merkle_root?
      !merkle_root_mutated? && calculate_merkle_root == header.merkle_root
    end

    # Whether the tx list is a mutation of another list with the same merkle root (CVE-2012-2459).
    # Duplicating the last tx of a level with an odd count leaves the root unchanged, and it shows up as
    # two identical hashes next to each other at some level of the tree. The last hash of an odd level is
    # paired with itself by construction and is not a mutation. See ComputeMerkleRoot in Bitcoin Core.
    # @return [Boolean]
    def merkle_root_mutated?
      hashes = transactions.map(&:tx_hash)
      while hashes.size > 1
        hashes.each_slice(2) { |left, right| return true if right && left == right }
        hashes << hashes.last if hashes.size.odd?
        hashes = hashes.each_slice(2).map { |left, right| Bitcoin.double_sha256([left + right].pack('H*')).bth }
      end
      false
    end

    # calculate merkle root from tx list.
    def calculate_merkle_root
      tree = Merkle::BinaryTree.new(config: Merkle::Config.bitcoin(element_encoding: :hex), leaves: transactions.map(&:tx_hash))
      tree.compute_root
    end

    # check the witness commitment in coinbase tx matches witness commitment calculated from tx list.
    def valid_witness_commitment?
      transactions[0].witness_commitment == calculate_witness_commitment
    end

    # calculate witness commitment from tx list.
    def calculate_witness_commitment
      witness_hashes = [COINBASE_WTXID]
      witness_hashes += (transactions[1..-1].map(&:witness_hash))
      reserved_value = transactions[0].inputs[0].script_witness.stack.map(&:bth).join
      tree = Merkle::BinaryTree.new(config: Merkle::Config.bitcoin(element_encoding: :hex), leaves: witness_hashes)
      root_hash = tree.compute_root
      Bitcoin.double_sha256([root_hash + reserved_value].pack('H*')).bth
    end

    # return this block height. block height is included in coinbase.
    # if block version under 1, height does not include in coinbase, so return nil.
    def height
      return nil if header.version < 2
      coinbase_tx = transactions[0]
      return nil unless coinbase_tx.coinbase_tx?
      buf = StringIO.new(coinbase_tx.inputs[0].script_sig.to_payload)
      len = Bitcoin.unpack_var_int_from_io(buf)
      buf.read(len).reverse.bth.to_i(16)
    end

  end
end