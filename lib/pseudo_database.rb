# frozen_string_literal: true

require 'json'

# Alternative to npm package `nosql`.
# https://github.com/petersirka/nosql
class PseudoDatabase
  include Enumerable

  attr_reader :path

  def initialize(path)
    @path = path
  end

  def each(&block)
    File.open(path).lazy.map { |line| JSON.parse(line, symbolize_names: true) }.each(&block)
  end

  def reset
    File.open(path, 'w').close
  end

  def insert(*hashes)
    File.open(path, 'a') do |file|
      file.puts(hashes.map(&:to_json))
    end
  end

  def replace(*hashes)
    File.open(path, 'w') do |file|
      file.puts(hashes.map(&:to_json))
    end
  end
end
