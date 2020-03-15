# frozen_string_literal: true

require 'sinatra'
require 'sinatra/json'

require_relative '../lib/pseudo_database'

AccessToken = Struct.new(:access_token, :scope, :user, keyword_init: true)

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
}.freeze

set :port, 9002

$db = PseudoDatabase.new(File.expand_path('../oauth-in-action-code/exercises/ch-4-ex-4/database.nosql', __dir__))

before do
  token = request.env['HTTP_AUTHORIZATION']&.slice(%r{^Bearer +([a-z0-9\-._‾+/]+=*)}i, 1) || params[:access_token]
  logger.info "Incoming token: #{token}"
  halt 401 if token.nil?

  access_token_hash = $db.find { |row| row[:access_token] == token }
  halt 401 if access_token_hash.nil?

  @access_token = AccessToken.new(**access_token_hash.slice(:access_token, :scope, :user))
end

get '/favorites' do
  user = @access_token.user || 'unknown'
  favorites = FAVORITES[user.to_sym] || { movies: [], foods: [], music: [] }
  json user: user, favorites: favorites.slice(*@access_token.scope.map(&:to_sym))
end
