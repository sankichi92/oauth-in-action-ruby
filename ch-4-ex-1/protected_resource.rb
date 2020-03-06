require 'json'

require 'sinatra'

DATA_PATH = File.expand_path('../oauth-in-action-code/exercises/ch-4-ex-1/database.nosql', __dir__)

set :port, 9002

before do
  access_token = request.env['HTTP_AUTHORIZATION']&.slice(%r{^Bearer +([a-z0-9\-._‾+/]+=*)}i, 1) || params[:access_token]
  logger.info "Incoming token: #{access_token}"
  error 401 if access_token.nil? || File.open(DATA_PATH).none? { |line| access_token == JSON.parse(line)['access_token'] }
end

post '/resource' do
  {
    name: 'Protected Resource',
    description: 'This data has been protected by OAuth 2.0'
  }.to_json
end
