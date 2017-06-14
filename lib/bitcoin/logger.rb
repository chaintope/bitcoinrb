require 'logger'

module Bitcoin

  # Simple Logger module
  module Logger

    # Create a logger with given +name+.log in $HOME/.bitcoinrb/log.
    def self.create(name, level = ::Logger::INFO)
      dir = "#{Bitcoin.base_dir}/log"
      FileUtils.mkdir_p(dir)
      logger = ::Logger.new(dir + "/#{name}.log", 10)
      logger.level = level
      logger
    end

  end
end