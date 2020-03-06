require 'json'

require 'sinatra'
require 'sinatra/json'

DATA_PATH = File.expand_path('../oauth-in-action-code/exercises/ch-4-ex-1/database.nosql', __dir__)

RESOURCE = {
  name: 'Protected Resource',
  description: 'This data has been protected by OAuth 2.0'
}

set :port, 9002

before do
  access_token = request.env['HTTP_AUTHORIZATION']&.slice(%r{^Bearer +([a-z0-9\-._‾+/]+=*)}i, 1) || params[:access_token]
  logger.info "Incoming token: #{access_token}"
  halt 401 if access_token.nil? || File.open(DATA_PATH).none? { |line| access_token == JSON.parse(line).fetch('access_token') }
end

post '/resource' do
  json RESOURCE
end
