require 'json'

require 'sinatra'

DATA_PATH = File.expand_path('../oauth-in-action-code/exercises/ch-4-ex-1/database.nosql', __dir__)

set :port, 9002

before do
  # TODO
end

post '/resource' do
  {
    name: 'Protected Resource',
    description: 'This data has been protected by OAuth 2.0'
  }.to_json
end
