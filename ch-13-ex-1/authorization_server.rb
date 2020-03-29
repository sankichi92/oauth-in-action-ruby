# frozen_string_literal: true

require 'openssl'
require 'securerandom'
require 'uri'

require 'jwt'
require 'rack/auth/basic'
require 'sinatra'
require 'sinatra/json'
require 'sinatra/required_params'

require_relative '../lib/pseudo_database'

Client = Struct.new(:id, :secret, :redirect_uris, :scope, keyword_init: true)
User = Struct.new(:sub, :preferred_username, :name, :email, :email_verified, keyword_init: true)

CLIENTS = [
  Client.new(
    id: 'oauth-client-1',
    secret: 'oauth-client-secret-1',
    redirect_uris: %w[http://localhost:9000/callback],
    scope: %w[openid profile email phone address],
  ),
].freeze

USERS = [
  User.new(
    sub: '9XE3-JI34-00132A',
    preferred_username: 'alice',
    name: 'Alice',
    email: 'alice.wonderland@example.com',
    email_verified: true,
  ),
  User.new(
    sub: '1ZT5-OE63-57383B',
    preferred_username: 'bob',
    name: 'Bob',
    email: 'bob.loblob@example.net',
    email_verified: false,
  ),
].freeze

RSA_KEY = <<~PEM
  -----BEGIN RSA PRIVATE KEY-----
  MIIEpAIBAAKCAQEA2pZzFsNJZV1pC3TSuD0xYbsjgNN+oM1uGjphK/ZOHfmTS/1d
  Sl2icr1bjV/T+oP8uy/LD5JHOxPvZhf9bgLxBtkBA19jr3l86k/wKQaThVnoeyE1
  dhUSd9qDvtWDuyzjg78st8Q9/M5Dk7Kzs/HaVQvZNFkczOnEHGKXWpFKOdlE5WhD
  LrBFgGeNt+vdvQE9MJGNnPXrRAVDYlkKPpLwL8HtmZqY+BeBUlk1MAMoRBn0PT0q
  zV2OXJnnev5UM2MO9lyMeWJaHw/7k/Ybf6gG8C/gc0goZwaavToM5bv2qRHckP/P
  uqfDsdgMGKVXm9GLLz5RqBqvvYLX263e7THYWwIDAQABAoIBAQDT9raNqTuABu+5
  A0TfEb/UFINeBjixt+N/nYLi/YpMuNpkAsG3Pksr1oFz+yv0ro6h+buAUwmtuSwZ
  pUPErSeKy12XJqXk3/sIwBGTxuPAmSm+VLqh0ddBz+yXXjbKh8Hr3LOBU9QEVQPk
  spJd+TYN6Fpsz8kEz96y48v/MAp5QnMXzBtRWHT0Mdp1Jd5Qa+mFNEbVBi/koqh4
  hb3rPO50LFMAT6Bds6q7aZ8iVI6Tkx8TAbARWWTmuDq2A7BDl25L0w/E7IrobubR
  EWmENalygZfq56hRJ+aMooU0MU6ou5GVmJfezgdlO7y7auYrG2aMCnapk1GMdPxO
  3nN0tDj5AoGBAPD3cSKSyPv5d3GQPJAobTIxrt0YCHa1eu/cwn24Lk2nRLixPKfy
  J0gnWlPtbVHHAE8FzRTiD5p++F1ce1jaGUU7ihBb0QLhcxO5v2wVquPo/NVzG+IV
  EABN+grh//15DoaIffEJTYzWPTmCtOxVF53aBl4hj81duxwpWGkFukBtAoGBAOg5
  lkqjVy3TfuzhHMPgjOWlKCUIDSh1quoZ/QSenZqSqU2nnkIM4xG9MBZClzAMaCIo
  FUOfp+s0W+OgS+wlHpTSUlbk+TO9Xa5dfmPSOjb2m1hTPc4GZGoysWJIen+mlocG
  NuoG1iamrUrVKw9jOVOFIGpTrYCteaNkA2lhMs7nAoGAW3IcHjnESlOe75sEUNT2
  s7DFIqSnOZ2fnP2TVbCa6d9Lpiek1DuCitBcaDNXZEx4IoUaEg3ETCZZTNz29n42
  Tt7Mg27EwCocyOSZ74O9iaZ2pO59K2xA2Uy+Unj39BKH36hW2y1jn8oCDBw9Wt7k
  CoSeHATylMY4ZvSN17VTvHUCgYEArW3UgAlcoizBLccw5Fhe4WJmiMFqkjzOV+bw
  vvJ2YWoGZqg32LwnGKhhsT4qCwg4/MlSmB40GcQQm/6qtMFEBYDNXXfDZJCX1hCc
  w4/NSh8CBQSls6eydl1FfFEEqzCOWmiZuk1AwbzYznpEnklMFsPlYYL8oIztusiG
  g7zDZSECgYB0lrU9G2D0n8zY9HCd8ytfCJlRFKJhqJb63QEghQcMUrvU3bm6kLtX
  WC16rAhuZsn46lgxjyviz1UUUx2tlhygGhEwG45pWv4ZIPd6S9T6yGUSZKy61hE1
  gVbjMuPkC8RYeWEgLoTckyKrtrX1pKMDh6PsXar38wsBGn7bFNx14A==
  -----END RSA PRIVATE KEY-----
PEM

$db = PseudoDatabase.new(File.expand_path('./database.nosql', __dir__)).tap(&:reset)
$requests = {}
$codes = {}

set :port, 9001

template :approve do
  <<~HTML
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <title>Authorization Server</title>
      </head>
      <body>
        <p>Approve this client?</p>
        <ul>
          <li>ID: <%= @client.id %></li>
        </ul>
        <form action="/approve" method="POST">
          <input type="hidden" name="request_id" value="<%= @request_id %>">
          <label for="user">Select user:</label>
          <select name="username" id="user">
            <option value="alice">Alice</option>
            <option value="bob">Bob</option>
          </select>
          <p>The client is requesting access to the following:</p>
          <ul>
            <% @scope.each do |scope| %>
              <li><label><input type="checkbox" name="scope[]" value="<%= scope %>" checked><%= scope %></label></li>
            <% end %>
          </ul>
          <input type="submit" name="approve" value="Approve">
          <input type="submit" name="deny" value="Deny">
        </form>
      </body>
    </html>
  HTML
end

helpers do
  def authenticate_client!
    auth = Rack::Auth::Basic::Request.new(request.env)
    client_id, client_secret = if auth.provided? && auth.basic?
                                 auth.credentials
                               else
                                 required_params :client_id, :client_secret
                                 [params[:client_id], params[:client_secret]]
                               end
    @client = get_client(client_id)
    halt 401, json(error: 'invalid_client') if @client.nil? || client_secret != @client.secret
  end

  def get_client(client_id)
    CLIENTS.find { |client| client.id == client_id }
  end

  def get_user(username)
    USERS.find { |user| user.preferred_username == username }
  end

  def generate_token
    SecureRandom.urlsafe_base64
  end

  def generate_jwt(sub:)
    now = Time.now
    payload = {
      iss: "http://#{settings.bind}:#{settings.port}/",
      sub: sub,
      aud: 'http://localhost:9002/',
      iat: now.to_i,
      exp: now.to_i + 5 * 60,
      jti: SecureRandom.alphanumeric(8),
    }

    rsa_private = OpenSSL::PKey::RSA.new(RSA_KEY)
    JWT.encode(payload, rsa_private, 'RS256', { type: 'JWT', kid: 'authserver' })
  end
end

get '/authorize' do
  required_params :response_type, :client_id, :redirect_uri, :scope

  @client = get_client(params[:client_id])
  halt 400, "Unknown client: #{escape(params[:client_id])}" if @client.nil?
  halt 400, "Invalid redirect URI: #{escape(params[:redirect_uri])}" unless @client.redirect_uris.include?(params[:redirect_uri])

  @scope = params[:scope].split
  halt 400, "Invalid scope: #{escape(params[:scope])}" unless @scope.difference(@client.scope).empty?

  @request_id = SecureRandom.uuid
  $requests[@request_id] = params

  erb :approve
end

post '/approve' do
  required_params :request_id

  original_params = $requests.delete(params[:request_id])
  halt 403, "No matching authorization request: #{escape(params[:request_id])}" if original_params.nil?

  query_hash = if params[:approve]
                 case original_params[:response_type]
                 when 'code'
                   client = get_client(original_params[:client_id])
                   if params[:scope].difference(client.scope).empty?
                     code = SecureRandom.alphanumeric(8)
                     $codes[code] = { request: original_params, scope: params[:scope], username: params[:username] }
                     { code: code }
                   else
                     { error: 'invalid_scope' }
                   end
                 else
                   { error: 'unsupported_response_type' }
                 end
               else
                 { error: 'access_denied' }
               end

  redirect_uri = URI.parse(original_params[:redirect_uri])
  redirect_uri.query = build_query(query_hash.merge(state: original_params[:state]).compact)
  redirect redirect_uri
end

post '/token' do
  authenticate_client!

  required_params :grant_type

  case params[:grant_type]
  when 'authorization_code'
    required_params :code

    code = $codes.delete(params[:code])
    if code && code[:request][:client_id] == @client.id
      # TODO
      access_token = generate_token
      user = get_user(code[:username])
      $db.insert({ access_token: access_token, client_id: @client.id, scope: code[:scope], user: user.to_h })
      json access_token: access_token, token_type: 'Bearer', scope: code[:scope].join(' ')
    else
      halt 400, json(error: 'invalid_grant')
    end
  else
    halt 400, json(error: 'unsupported_grant_type')
  end
end
