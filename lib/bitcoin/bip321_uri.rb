require 'uri'
require 'cgi'
require 'bigdecimal'

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
        validate_amount!(amount)
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

      if sp
        raise ArgumentError, "sp must be string." unless sp.is_a?(String)
        begin
          Bech32::SilentPaymentAddr.parse(sp)
          @sp = sp
        rescue ArgumentError
          raise ArgumentError, "Invalid sp address specified."
        end
      end

      raise ArgumentError, 'pop is required, if req_pop is true.' if req_pop && pop.nil?
      @req_pop = req_pop

      @query_addrs = query_addrs.map do |addr|
        Bitcoin::Script.parse_from_addr(addr)
        addr
      end

      raise ArgumentError, "other_params must be Hash." unless other_params.is_a?(Hash)
      other_params.keys.each do |key|
        raise ArgumentError, 'An unsupported reqparam is included.' if key.downcase.start_with?('req-')
      end
      @other_params = other_params
    end

    # The keys which hold one value. BIP-321 forbids a second label, message, pop or amount, and this
    # class holds one value for the other payment instructions it knows.
    SINGLE_VALUE_KEYS = %w[amount label message pop lightning lno pay sp].freeze
    # The largest amount a URI may ask for, in BTC.
    MAX_AMOUNT = BigDecimal(21_000_000)

    # Parse BIP-321 URI string.
    # The scheme and the query keys are case-insensitive, values are percent-decoded as RFC 3986 says
    # (a '+' stays a '+'), the amount has to match the grammar *digit ["." *digit], and a key which is not
    # known here may appear more than once, in which case its values are collected in an Array.
    # @param [String] BIP-321 URI.
    # @return [Bitcoin::BIP321URI]
    # @raise [ArgumentError]
    def self.parse(uri)
      raise ArgumentError, "uri must be string." unless uri.is_a?(String)
      raise ArgumentError, "Invalid uri scheme." unless uri.downcase.start_with?('bitcoin:')
      body, query = uri[8..-1].split('?', 2)
      addr = body.nil? || body.empty? ? nil : body
      params = {}
      others = {}
      req_pop = false
      query_addrs = []
      (query ? query.split('&') : []).each do |pair|
        next if pair.empty?
        raw_key, raw_value = pair.split('=', 2)
        key = percent_decode(raw_key).downcase
        next if key.empty?
        value = raw_value.nil? ? nil : percent_decode(raw_value)
        if key == 'req-pop'
          req_pop = true
          key = 'pop'
        end
        if %w[bc tb bcrt].include?(key)
          raise ArgumentError, "#{key} not allowed in current network." unless Bitcoin.chain_params.bech32_hrp == key
          # The key names the human readable part of the address it carries.
          raise ArgumentError, "#{key} must hold a bech32 address with the prefix #{key}." unless value.to_s.downcase.start_with?("#{key}1")
          query_addrs << value
        elsif SINGLE_VALUE_KEYS.include?(key)
          raise ArgumentError, "#{key} must not appear twice." if params.key?(key)
          params[key] = value
        else
          raise ArgumentError, 'An unsupported reqparam is included.' if key.start_with?('req-')
          # BIP-321: a key this implementation does not know may appear more than once. The values are kept in
          # order, and a key given without a value is kept as nil.
          others[key] = if others.key?(key)
                          values = others[key].is_a?(Array) ? others[key] : [others[key]]
                          values + [value]
                        else
                          value
                        end
        end
      end
      amount = params['amount'] ? parse_amount(params['amount']) : nil
      BIP321URI.new(address: addr, amount: amount, label: params['label'], message: params['message'],
                    pop: params['pop'], lightning: params['lightning'], lno: params['lno'],
                    pay: params['pay'], sp: params['sp'], other_params: others, req_pop: req_pop, query_addrs: query_addrs)
    end

    # Parse the value of an amount parameter.
    # @param [String] str The value, which has to be *digit ["." *digit] with at most 8 decimal places.
    # @return [BigDecimal]
    # @raise [ArgumentError]
    def self.parse_amount(str)
      m = str.match(/\A([0-9]*)(?:\.([0-9]*))?\z/)
      raise ArgumentError, "Invalid amount: #{str}" if m.nil? || (m[1].empty? && m[2].to_s.empty?)
      raise ArgumentError, "Invalid amount: #{str}. An amount has at most 8 decimal places." if m[2].to_s.length > 8
      amount = BigDecimal(str.end_with?('.') ? str + '0' : (str.start_with?('.') ? '0' + str : str))
      raise ArgumentError, "Invalid amount: #{str}. It exceeds #{MAX_AMOUNT.to_i} BTC." if amount > MAX_AMOUNT
      amount
    end

    # Percent-decode a URI component as RFC 3986 does. Unlike form decoding, a '+' is a literal '+'.
    # @param [String] str
    # @return [String]
    def self.percent_decode(str)
      URI.decode_www_form_component(str.gsub('+', '%2B'))
    end

    private_class_method :parse_amount, :percent_decode

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
      params = all_params.flat_map do |k, values|
        values = values.nil? ? [nil] : Array(values) # a key given without a value is written as the key alone
        values.map { |v| v.nil? ? k : "#{k}=#{CGI.escape(v).gsub('+', '%20')}" }
      end
      params += query_addrs.map {|addr| "#{Bitcoin.chain_params.bech32_hrp}=#{addr}"}
      uri << "?#{params.join('&')}" unless params.empty?
      uri
    end

    private

    # @raise [ArgumentError] If +amount+ is negative, above MAX_AMOUNT or finer than a satoshi.
    def validate_amount!(amount)
      raise ArgumentError, 'amount must not be negative.' if amount.negative?
      raise ArgumentError, "amount must not exceed #{MAX_AMOUNT.to_i} BTC." if amount > MAX_AMOUNT
      raise ArgumentError, 'amount must not have more than 8 decimal places.' unless (amount * 100_000_000).frac.zero?
    end
  end
end