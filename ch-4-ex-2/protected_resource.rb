require 'json'

require 'sinatra'
require 'sinatra/json'

DATA_PATH = File.expand_path('../oauth-in-action-code/exercises/ch-4-ex-2/database.nosql', __dir__)

AccessToken = Struct.new(:access_token, :scope)

set :port, 9002

enable :method_override

helpers do
  def require_scope(scope)
    unless @access_token.scope.include?(scope)
      headers 'WWW-Authenticate' => %(Bearer realm=#{settings.bind}:#{settings.port}, error="insufficient_scope", scope="#{scope}")
      error 403
    end
  end
end

before do
  token = request.env['HTTP_AUTHORIZATION']&.slice(%r{^Bearer +([a-z0-9\-._‾+/]+=*)}i, 1) || params[:access_token]
  logger.info "Incoming token: #{token}"
  error 401 if token.nil?

  File.open(DATA_PATH).each do |line|
    access_token_hash = JSON.parse(line)
    if token == access_token_hash['access_token']
      @access_token = AccessToken.new(access_token_hash['access_token'], access_token_hash.fetch('scope'))
      break
    end
  end
  error 401 if @access_token.nil?
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
