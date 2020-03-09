# frozen_string_literal: true

require 'sinatra'
require 'sinatra/json'

require_relative '../lib/pseudo_database'

AccessToken = Struct.new(:access_token, :scope)

set :port, 9002

enable :method_override

$db = PseudoDatabase.new(File.expand_path('../oauth-in-action-code/exercises/ch-4-ex-2/database.nosql', __dir__))

helpers do
  def require_scope(scope)
    unless @access_token.scope.include?(scope)
      headers 'WWW-Authenticate' => %(Bearer realm=#{settings.bind}:#{settings.port}, error="insufficient_scope", scope="#{scope}")
      halt 403
    end
  end
end

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

$words = []

get '/words' do
  require_scope 'read'
  json words: $words.join(' '), timestamp: Time.now.to_i
end

post '/words' do
  require_scope 'write'
  $words.push(params[:word]) if params[:word]
  halt 201
end

delete '/words' do
  require_scope 'delete'
  $words.pop
  halt 204
end
