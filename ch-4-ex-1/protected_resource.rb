# frozen_string_literal: true

require 'sinatra'
require 'sinatra/json'

require_relative '../lib/pseudo_database'

RESOURCE = {
  name: 'Protected Resource',
  description: 'This data has been protected by OAuth 2.0',
}.freeze

set :port, 9002

$db = PseudoDatabase.new(File.expand_path('../oauth-in-action-code/exercises/ch-4-ex-1/database.nosql', __dir__))

before do
  access_token = request.env['HTTP_AUTHORIZATION']&.slice(%r{^Bearer +([a-z0-9\-._‾+/]+=*)}i, 1) || params[:access_token]
  logger.info "Incoming token: #{access_token}"
  halt 401 if access_token.nil? || $db.none? { |row| row[:access_token] == access_token }
end

post '/resource' do
  json RESOURCE
end
