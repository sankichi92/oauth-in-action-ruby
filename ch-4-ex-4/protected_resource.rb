require 'json'

require 'sinatra'
require 'sinatra/json'

DATA_PATH = File.expand_path('../oauth-in-action-code/exercises/ch-4-ex-4/database.nosql', __dir__)

FAVORITES = {
  alice: {
    movies: ['The Multidmensional Vector', 'Space Fights', 'Jewelry Boss'],
    foods: ['bacon', 'pizza', 'bacon pizza'],
    music: ['techno', 'industrial', 'alternative'],
  },
  bob: {
    movies: ['An Unrequited Love', 'Several Shades of Turquoise', 'Think Of The Children'],
    foods: ['bacon', 'kale', 'gravel'],
    music: ['baroque', 'ukulele', 'baroque ukulele'],
  },
  unknown: {
    movies: [],
    foods: [],
    music: [],
  },
}

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

get '/favorites' do
  # TODO
  json FAVORITES[:unknown]
end
