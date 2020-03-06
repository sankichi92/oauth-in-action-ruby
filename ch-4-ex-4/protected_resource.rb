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

AccessToken = Struct.new(:access_token, :scope, :user, keyword_init: true)

set :port, 9002

before do
  token = request.env['HTTP_AUTHORIZATION']&.slice(%r{^Bearer +([a-z0-9\-._‾+/]+=*)}i, 1) || params[:access_token]
  logger.info "Incoming token: #{token}"
  halt 401 if token.nil?

  File.open(DATA_PATH).each do |line|
    access_token_hash = JSON.parse(line, symbolize_names: true)
    if token == access_token_hash[:access_token]
      @access_token = AccessToken.new(**access_token_hash.slice(:access_token, :scope, :user))
      break
    end
  end
  halt 401 if @access_token.nil?
end

get '/favorites' do
  favorites = FAVORITES[@access_token.user.to_sym] || FAVORITES[:unknown]
  json user: @access_token.user, favorites: favorites.slice(*@access_token.scope.map(&:to_sym))
end
