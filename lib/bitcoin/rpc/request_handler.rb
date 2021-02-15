module Bitcoin
  module RPC

    # RPC server's request handler.
    module RequestHandler

      # Returns an object containing various state info regarding blockchain processing.
      def getblockchaininfo
        h = {}
        h[:chain] = Bitcoin.chain_params.network
        best_block = node.chain.latest_block
        h[:headers] = best_block.height
        h[:bestblockhash] = best_block.header.block_id
        h[:chainwork] = best_block.header.work
        h[:mediantime] = node.chain.mtp(best_block.block_hash)
        h
      end

      # shutdown node
      def stop
        node.shutdown
      end

      # get block header information.
      # @param [String] block_id block hash(big endian)
      def getblockheader(block_id, verbose)
        block_hash = block_id.rhex
        entry = node.chain.find_entry_by_hash(block_hash)
        raise ArgumentError.new('Block not found') unless entry
        if verbose
          {
              hash: block_id,
              height: entry.height,
              version: entry.header.version,
              versionHex: entry.header.version.to_even_length_hex,
              merkleroot: entry.header.merkle_root.rhex,
              time: entry.header.time,
              mediantime: node.chain.mtp(block_hash),
              nonce: entry.header.nonce,
              bits: entry.header.bits.to_even_length_hex,
              previousblockhash: entry.prev_hash.rhex,
              nextblockhash: node.chain.next_hash(block_hash).rhex
          }
        else
          entry.header.to_hex
        end
      end

      # Returns connected peer information.
      def getpeerinfo
        node.pool.peers.map do |peer|
          local_addr = "#{peer.remote_version.remote_addr.addr_string}:18333"
          {
            id: peer.id,
            addr: "#{peer.host}:#{peer.port}",
            addrlocal: local_addr,
            services: peer.remote_version.services.to_even_length_hex.rjust(16, '0'),
            relaytxes: peer.remote_version.relay,
            lastsend: peer.last_send,
            lastrecv: peer.last_recv,
            bytessent: peer.bytes_sent,
            bytesrecv: peer.bytes_recv,
            conntime: peer.conn_time,
            pingtime: peer.ping_time,
            minping: peer.min_ping,
            version: peer.remote_version.version,
            subver: peer.remote_version.user_agent,
            inbound: !peer.outbound?,
            startingheight: peer.remote_version.start_height,
            best_hash: peer.best_hash,
            best_height: peer.best_height
          }
        end
      end

      # broadcast transaction
      def sendrawtransaction(hex_tx)
        tx = Bitcoin::Tx.parse_from_payload(hex_tx.htb)
        # TODO check wether tx is valid
        node.broadcast(tx)
        tx.txid
      end

      # decode tx data.
      def decoderawtransaction(hex_tx)
        begin
          Bitcoin::Tx.parse_from_payload(hex_tx.htb).to_h
        rescue Exception
          raise ArgumentError.new('TX decode failed')
        end
      end

      # decode script data.
      def decodescript(hex_script)
        begin
          script = Bitcoin::Script.parse_from_payload(hex_script.htb)
          h = script.to_h
          h.delete(:hex)
          h[:p2sh] = script.to_p2sh.to_addr unless script.p2sh?
          h
        rescue Exception
          raise ArgumentError.new('Script decode failed')
        end
      end

      # wallet api

      # create wallet
      def createwallet(wallet_id = 1, wallet_path_prefix = Bitcoin::Wallet::Base.default_path_prefix)
        wallet = Bitcoin::Wallet::Base.create(wallet_id, wallet_path_prefix)
        node.wallet = wallet unless node.wallet
        {wallet_id: wallet.wallet_id, mnemonic: wallet.master_key.mnemonic}
      end

      # get wallet list.
      def listwallets(wallet_path_prefix = Bitcoin::Wallet::Base.default_path_prefix)
        Bitcoin::Wallet::Base.wallet_paths(wallet_path_prefix)
      end

      # get current wallet information.
      def getwalletinfo
        node.wallet ? node.wallet.to_h : {}
      end

      # get the list of current Wallet accounts.
      def listaccounts
        return {} unless node.wallet
        accounts = {}
        node.wallet.accounts.each do |a|
          accounts[a.name] = node.wallet.get_balance(a)
        end
        accounts
      end

      # encrypt wallet.
      def encryptwallet(passphrase)
        return nil unless node.wallet
        node.wallet.encrypt(passphrase)
        "The wallet 'wallet_id: #{node.wallet.wallet_id}' has been encrypted."
      end

      # create new bitcoin address for receiving payments.
      def getnewaddress(account_name)
        node.wallet.generate_new_address(account_name)
      end

    end

  end
end
