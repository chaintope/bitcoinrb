require 'uri'
require 'cgi'

module Bitcoin
  # BIP-321 URI
  # @see https://github.com/bitcoin/bips/blob/master/bip-0321.mediawiki
  class BIP321URI

    attr_reader :addr
    attr_reader :amount
    attr_reader :label
    attr_reader :message
    attr_reader :pop # proof of payment
    attr_reader :lightning # BOLT11 invoice
    attr_reader :lno # BOLT12 offer
    attr_reader :pay # BIP-351 private address
    attr_reader :sp # BIP-352 silent payment address
    attr_reader :req_pop
    attr_reader :query_addrs

    attr_reader :other_params

    # Constructor
    # @param [String] address
    # @param [BigDecimal, Integer] amount
    # @param [String] label
    # @param [String] message
    # @param [Hash] other_params
    # @param [String] pop
    # @param [String] lightning BOLT11 invoice.
    # @param [String] lno BOLT12 offer.
    # @param [String] pay BIP-351 private address.
    # @param [String] sp BIP-352 silent payment address.
    # @param [Boolean] req_pop whether pop is required or not.
    # @param [Array] query_addrs A list of addresses to be placed as query parameters.
    def initialize(address: nil, amount: nil, label: nil, message: nil, other_params: {},
                   pop:nil, lightning: nil, lno: nil, pay:nil, sp: nil, req_pop: false, query_addrs: [])
      if address
        Bitcoin::Script.parse_from_addr(address)
        @addr = address
      end
      if amount
        amount = BigDecimal(amount) if amount.is_a?(Integer)
        raise ArgumentError, "amount must be BigDecimal or integer." unless amount.is_a?(BigDecimal)
        @amount = amount
      end
      raise ArgumentError, "label must be string." if label && !label.is_a?(String)
      @label = label

      raise ArgumentError, "message must be string." if message && !message.is_a?(String)
      @message = message

      raise ArgumentError, "pop must be string." if pop && !pop.is_a?(String)
      @pop = pop

      raise ArgumentError, "lightning must be string." if lightning && !lightning.is_a?(String)
      @lightning = lightning

      raise ArgumentError, "lno must be string." if lno && !lno.is_a?(String)
      @lno = lno

      raise ArgumentError, "pay must be string." if pay && !pay.is_a?(String)
      @pay = pay

      raise ArgumentError, "sp must be string." if sp && !sp.is_a?(String)
      @sp = sp

      raise ArgumentError, 'pop is required, if req_pop is true.' if req_pop && pop.nil?
      @req_pop = req_pop

      @query_addrs = query_addrs.map do |addr|
        Bitcoin::Script.parse_from_addr(addr)
        addr
      end

      raise ArgumentError, "other_params must be Hash." unless other_params.is_a?(Hash)
      other_params.keys.each do |key|
        raise ArgumentError, 'An unsupported reqparam is included.' if key.start_with?('req-')
      end
      @other_params = other_params
    end

    # Parse BIP-321 URI string.
    # @param [String] BIP-321 URI.
    # @return [Bitcoin::BIP321URI]
    # @raise [ArgumentError]
    def self.parse(uri)
      raise ArgumentError, "uri must be string." unless uri.is_a?(String)
      raise ArgumentError, "Invalid uri scheme." unless uri.downcase.start_with?('bitcoin:')
      uri = uri[8..-1]
      addr, params = uri.split('?', 2)
      req_pop = false
      query_addrs = []
      params = if params
                 decoded = URI.decode_www_form(params)
                 decoded = decoded.map do |k, v|
                   if k == 'req-pop'
                     req_pop = true
                     k = 'pop'
                   end
                   if %w[bc tb].include?(k.downcase)
                     raise ArgumentError, "#{k} not allowed in current network." unless Bitcoin.chain_params.bech32_hrp == k.downcase
                     query_addrs << v
                     nil
                   else
                     [k, v]
                   end
                 end.compact
                 keys = decoded.map(&:first)
                 duplicate_key = keys.detect { |key| keys.count(key) > 1 }
                 raise ArgumentError, "#{duplicate_key} must not appear twice." if duplicate_key
                 decoded.to_h.except('')
               else
                 {}
               end
      addr = nil if addr.empty?
      amount = params['amount'] ? BigDecimal(params['amount']) : nil
      excluded_keys = %w[amount label message pop lightning lno pay sp]
      others = params.except(*excluded_keys)
      BIP321URI.new(address: addr, amount: amount, label: params['label'], message: params['message'],
                    pop: params['pop'], lightning: params['lightning'], lno: params['lno'],
                    pay: params['pay'], sp: params['sp'], other_params: others, req_pop: req_pop, query_addrs: query_addrs)
    end

    # Get all addresses contained in the URI body and query parameters
    # @return [Array] An array of address.
    def addresses
      addrs = []
      addrs << @addr if @addr
      addrs + @query_addrs
    end

    # Payment amount (satoshi unit)
    # @return [Integer, nil]
    def satoshi
      amount.nil? ? nil : (amount * 100_000_000).to_i
    end

    def to_s
      uri = 'bitcoin:'
      uri << addr if addr
      base_params = {}
      base_params['amount'] = amount.to_s('f').sub(/\.0+$/, '') if amount
      base_params['label'] = label if label
      base_params['message'] = message if message
      pop_label = req_pop ? 'req-pop' : 'pop'
      base_params[pop_label] = pop if pop
      base_params['lightning'] = lightning if lightning
      base_params['lno'] = lno if lno
      base_params['sp'] = sp if sp
      base_params['pay'] = pay if pay

      all_params = base_params.merge other_params
      params = all_params.map do |k, v|
        "#{k}=#{CGI.escape(v).gsub('+', '%20')}"
      end.join('&')
      uri << "?#{params}" unless params.empty?
      unless query_addrs.empty?
        uri << '?' unless uri.include?('?')
        uri << query_addrs.map {|addr| "#{Bitcoin.chain_params.bech32_hrp}=#{addr}"}.join('&')
      end
      uri
    end
  end
end