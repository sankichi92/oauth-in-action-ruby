# frozen_string_literal: true

require 'sinatra'
require 'sinatra/json'
require 'sinatra/multi_route'

require_relative '../lib/pseudo_database'

AccessToken = Struct.new(:access_token, :scope)
User = Struct.new(:sub, :preferred_username, :name, :email, :email_verified, keyword_init: true)

$db = PseudoDatabase.new(File.expand_path('./database.nosql', __dir__))

set :port, 9002

before do
  token = request.env['HTTP_AUTHORIZATION']&.slice(%r{^Bearer +([a-z0-9\-._‾+/]+=*)}i, 1) || params[:access_token]
  logger.info "Incoming token: #{token}"
  halt 401 if token.nil?

  access_token_hash = $db.find { |row| row[:access_token] == token }
  halt 401 if access_token_hash.nil?

  @user = User.new(**access_token_hash[:user]) if access_token_hash[:user]
  @access_token = AccessToken.new(access_token_hash[:access_token], access_token_hash[:scope])
end

post '/resource' do
  json(
    name: 'Protected Resource',
    description: 'This data has been protected by OAuth 2.0',
  )
end

route :get, :post, '/userinfo' do
  halt 403 unless @access_token.scope.include?('openid')
  halt 404 if @user.nil?

  response_body = { sub: @user.sub }
  @access_token.scope.each do |scope|
    case scope
    when 'profile'
      response_body.merge!(
        @user.to_h.slice(:name, :family_name, :given_name, :middle_name, :nickname, :preferred_username, :profile, :picture, :website, :gender, :birthdate,
                         :zoneinfo, :locale, :updated_at),
      )
    when 'email'
      response_body.merge!(@user.to_h.slice(:email, :email_verified))
    when 'address'
      response_body.merge!(@user.to_h.slice(:address))
    when 'phone'
      response_body.merge!(@user.to_h.slice(:phone_number, :phone_number_verified))
    end
  end

  json response_body
end
