# frozen_string_literal: true

require 'json'

require 'sinatra'
require 'sinatra/json'

DATA_PATH = File.expand_path('../oauth-in-action-code/exercises/ch-4-ex-3/database.nosql', __dir__)

PRODUCE = {
  fruit: %w[apple banana kiwi],
  veggies: %w[lettuce onion potato],
  meats: %w[bacon steak chicken\ breast],
}.freeze

AccessToken = Struct.new(:access_token, :scope)

set :port, 9002

before do
  token = request.env['HTTP_AUTHORIZATION']&.slice(%r{^Bearer +([a-z0-9\-._‾+/]+=*)}i, 1) || params[:access_token]
  logger.info "Incoming token: #{token}"
  halt 401 if token.nil?

  File.open(DATA_PATH).each do |line|
    access_token_hash = JSON.parse(line)
    if token == access_token_hash['access_token']
      @access_token = AccessToken.new(access_token_hash['access_token'], access_token_hash.fetch('scope'))
      break
    end
  end
  halt 401 if @access_token.nil?
end

get '/produce' do
  json PRODUCE.slice(*@access_token.scope.map(&:to_sym))
end
