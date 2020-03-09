# frozen_string_literal: true

require 'sinatra'
require 'sinatra/json'

require_relative '../lib/pseudo_database'

PRODUCE = {
  fruit: %w[apple banana kiwi],
  veggies: %w[lettuce onion potato],
  meats: %w[bacon steak chicken\ breast],
}.freeze

AccessToken = Struct.new(:access_token, :scope)

set :port, 9002

$db = PseudoDatabase.new(File.expand_path('../oauth-in-action-code/exercises/ch-4-ex-3/database.nosql', __dir__))

before do
  token = request.env['HTTP_AUTHORIZATION']&.slice(%r{^Bearer +([a-z0-9\-._‾+/]+=*)}i, 1) || params[:access_token]
  logger.info "Incoming token: #{token}"
  halt 401 if token.nil?

  access_token_hash = $db.find { |row| row[:access_token] == token }
  if access_token_hash
    @access_token = AccessToken.new(access_token_hash.fetch(:access_token), access_token_hash.fetch(:scope))
  else
    halt 401
  end
end

get '/produce' do
  json PRODUCE.slice(*@access_token.scope.map(&:to_sym))
end
